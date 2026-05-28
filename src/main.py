"""Betterleaks Cloud - Apify actor (full upstream parity + global_github layer).

Modes:
  github         - run `betterleaks github <url>` (org/user/repo/PR/issue/gist)
  global_github  - our addition: GitHub Code Search picks unique repos,
                   then `betterleaks git` runs against each (parallel)
  git            - run `betterleaks git <url>`
  s3             - run `betterleaks s3 <url>`
  dir            - download a tarball, extract, run `betterleaks dir`
  stdin          - pipe text content into `betterleaks stdin`

Every CLI flag the upstream tool accepts is exposed as an INPUT_SCHEMA field.
Findings are emitted to the default dataset as raw betterleaks Finding records,
no transformation.
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import urllib.parse
import zipfile
from pathlib import Path

from apify import Actor

from src.code_search import CodeSearchClient, CodeSearchError, discover_unique_repos

log = logging.getLogger("betterleaks-cloud")

BL_BIN = "betterleaks"
REPORT_TIMEOUT = 1800           # 30 min per subprocess (single repo)
GLOBAL_PER_REPO_TIMEOUT = 600   # 10 min per repo in global mode
MAX_PARALLEL_GLOBAL = 4


# ────────────────────────────────────────────────────────────────────────────
# Argument builder - translate inputs into a betterleaks argv
# ────────────────────────────────────────────────────────────────────────────


def _bool_flag(cmd: list[str], flag: str, value) -> None:
    if value:
        cmd.append(flag)


def _add_global_flags(cmd: list[str], inputs: dict, report_path: Path, config_path: Path | None) -> None:
    """Flags that apply to every subcommand (root-level)."""
    cmd += ["--report-format", "json", "--report-path", str(report_path)]
    if not inputs.get("exit_on_findings", True):
        cmd += ["--exit-code", "0"]

    # Output / display
    if (r := inputs.get("redact")) is not None and int(r) > 0:
        cmd += ["--redact", str(int(r))]
    if mc := inputs.get("match_context"):
        cmd += ["--match-context", mc]
    if inputs.get("verbose"):
        cmd.append("-v")
    if ll := inputs.get("log_level"):
        cmd += ["--log-level", ll]
    _bool_flag(cmd, "--legacy-print", inputs.get("legacy_print"))
    _bool_flag(cmd, "--no-color", inputs.get("no_color", True))
    _bool_flag(cmd, "--no-banner", inputs.get("no_banner", True))

    # Rule control
    for rid in (inputs.get("enable_rule") or []):
        cmd += ["--enable-rule", rid]
    if config_path is not None:
        cmd += ["--config", str(config_path)]
    _bool_flag(cmd, "--ignore-gitleaks-allow", inputs.get("ignore_gitleaks_allow"))
    if igp := inputs.get("gitleaks_ignore_path"):
        cmd += ["--gitleaks-ignore-path", igp]

    # Limits
    if (mtm := inputs.get("max_target_megabytes")) is not None:
        cmd += ["--max-target-megabytes", str(int(mtm))]
    if (mad := inputs.get("max_archive_depth")) is not None and int(mad) > 0:
        cmd += ["--max-archive-depth", str(int(mad))]
    if (mdd := inputs.get("max_decode_depth")) is not None:
        cmd += ["--max-decode-depth", str(int(mdd))]
    if (to := inputs.get("timeout_seconds")) is not None and int(to) > 0:
        cmd += ["--timeout", str(int(to))]
    if rge := inputs.get("regex_engine"):
        cmd += ["--regex-engine", rge]
    if ex := inputs.get("experiments"):
        cmd += ["--experiments", ex]

    # Validation
    if inputs.get("validation"):
        cmd.append("--validation")
        if (vt := inputs.get("validation_timeout")) is not None and int(vt) > 0:
            cmd += ["--validation-timeout", f"{int(vt)}s"]
        if (vw := inputs.get("validation_workers")) is not None and int(vw) > 0:
            cmd += ["--validation-workers", str(int(vw))]
        _bool_flag(cmd, "--validation-debug", inputs.get("validation_debug"))
        _bool_flag(cmd, "--validation-extract-empty", inputs.get("validation_extract_empty"))
        if vs := inputs.get("validation_status"):
            cmd += ["--validation-status", vs]
        if vev := inputs.get("validation_env_vars"):
            cmd += ["--validation-env-vars", vev]

    # Diagnostics
    if diag := inputs.get("diagnostics"):
        cmd += ["--diagnostics", diag]

    # Baseline
    # NOTE: baseline_url is downloaded by main flow into a local file -
    # the --baseline-path is added when that file is ready.


def build_github_cmd(inputs: dict, target: str, report_path: Path, config_path: Path | None) -> list[str]:
    cmd = [BL_BIN, "github", target]
    _add_global_flags(cmd, inputs, report_path, config_path)
    if token := inputs.get("github_token"):
        cmd += ["--token", token]
    if includes := inputs.get("include"):
        cmd += ["--include", ",".join(includes)]
    if excludes := inputs.get("exclude"):
        cmd += ["--exclude", ",".join(excludes)]
    for pat in (inputs.get("exclude_repo") or []):
        cmd += ["--exclude-repo", pat]
    for wf in (inputs.get("actions_workflow") or []):
        cmd += ["--actions-workflow", wf]
    if since := inputs.get("since"):
        cmd += ["--since", since[:10] if len(since) > 10 else since]
    if until := inputs.get("until"):
        cmd += ["--until", until[:10] if len(until) > 10 else until]
    if (gw := inputs.get("git_workers")) is not None:
        cmd += ["--git-workers", str(int(gw))]
    if lo := inputs.get("log_opts"):
        cmd += ["--log-opts", lo]
    return cmd


def build_git_cmd(inputs: dict, target: str, report_path: Path, config_path: Path | None) -> list[str]:
    cmd = [BL_BIN, "git", target]
    _add_global_flags(cmd, inputs, report_path, config_path)
    if (gw := inputs.get("git_workers")) is not None:
        cmd += ["--git-workers", str(int(gw))]
    if lo := inputs.get("log_opts"):
        cmd += ["--log-opts", lo]
    if plat := inputs.get("git_platform"):
        cmd += ["--platform", plat]
    return cmd


def build_s3_cmd(inputs: dict, target: str, report_path: Path, config_path: Path | None) -> list[str]:
    cmd = [BL_BIN, "s3", target]
    _add_global_flags(cmd, inputs, report_path, config_path)
    if inputs.get("s3_anonymous"):
        cmd.append("--anonymous")
    else:
        if ak := inputs.get("s3_access_key"):
            cmd += ["--access-key", ak]
        if sk := inputs.get("s3_secret_key"):
            cmd += ["--secret-key", sk]
        if st := inputs.get("s3_session_token"):
            cmd += ["--session-token", st]
    if rg := inputs.get("s3_region"):
        cmd += ["--region", rg]
    if (mos := inputs.get("s3_max_object_size")) is not None and int(mos) > 0:
        cmd += ["--max-object-size", str(int(mos))]
    if (sw := inputs.get("s3_workers")) is not None and int(sw) > 0:
        cmd += ["--workers", str(int(sw))]
    return cmd


def build_dir_cmd(inputs: dict, dir_path: Path, report_path: Path, config_path: Path | None) -> list[str]:
    cmd = [BL_BIN, "dir", str(dir_path)]
    _add_global_flags(cmd, inputs, report_path, config_path)
    _bool_flag(cmd, "--follow-symlinks", inputs.get("dir_follow_symlinks"))
    return cmd


def build_stdin_cmd(inputs: dict, report_path: Path, config_path: Path | None) -> list[str]:
    cmd = [BL_BIN, "stdin"]
    _add_global_flags(cmd, inputs, report_path, config_path)
    return cmd


# ────────────────────────────────────────────────────────────────────────────
# Helpers for dir / baseline / config TOML
# ────────────────────────────────────────────────────────────────────────────


def _write_temp_text(content: str, suffix: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.flush()
    f.close()
    return Path(f.name)


def _download_to_temp(url: str, suffix: str = "") -> Path:
    tmp = tempfile.NamedTemporaryFile(mode="wb", suffix=suffix, delete=False)
    tmp.close()
    with urllib.request.urlopen(url, timeout=120) as resp:
        with open(tmp.name, "wb") as out:
            shutil.copyfileobj(resp, out)
    return Path(tmp.name)


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    """Extract a tar.gz or zip into dest_dir."""
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(dest_dir)
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        mode = "r:gz" if name.endswith((".tar.gz", ".tgz")) else "r"
        with tarfile.open(archive_path, mode) as t:
            t.extractall(dest_dir)
    else:
        # Try tar then zip
        try:
            with tarfile.open(archive_path) as t:
                t.extractall(dest_dir)
        except Exception:
            with zipfile.ZipFile(archive_path) as z:
                z.extractall(dest_dir)


def _redact_cmd_for_log(cmd: list[str]) -> str:
    masked, skip_next = [], False
    sensitive = {"--token", "--access-key", "--secret-key", "--session-token"}
    for tok in cmd:
        if skip_next:
            masked.append("<redacted>")
            skip_next = False
            continue
        if tok in sensitive:
            masked.append(tok)
            skip_next = True
            continue
        masked.append(tok)
    return shlex.join(masked)


# ────────────────────────────────────────────────────────────────────────────
# Subprocess runner
# ────────────────────────────────────────────────────────────────────────────


def run_betterleaks(
    cmd: list[str],
    stdin_input: str | None = None,
    timeout: int = REPORT_TIMEOUT,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=stdin_input,
        timeout=timeout,
    )


# ────────────────────────────────────────────────────────────────────────────
# Main entry
# ────────────────────────────────────────────────────────────────────────────


async def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    async with Actor:
        try:
            await Actor.charge("actor_start")
        except Exception:
            pass

        inputs = await Actor.get_input() or {}
        mode = inputs.get("mode", "github")

        # Verify binary
        try:
            v = subprocess.run([BL_BIN, "version"], capture_output=True, text=True, timeout=10)
            Actor.log.info("betterleaks version: %s", v.stdout.strip())
        except Exception as exc:
            await Actor.fail(status_message=f"betterleaks binary not invocable: {exc}")
            return

        # Optional custom config TOML
        config_path: Path | None = None
        if cfg := inputs.get("custom_config_toml"):
            config_path = _write_temp_text(cfg, ".toml")
            Actor.log.info("custom config: %s", config_path)

        # Baseline download
        if bl_url := inputs.get("baseline_url"):
            try:
                bl_path = _download_to_temp(bl_url, ".json")
                inputs["_baseline_path"] = str(bl_path)
                Actor.log.info("baseline downloaded to %s", bl_path)
            except Exception as exc:
                Actor.log.warning("baseline download failed: %s", exc)

        # Report template
        if rt := inputs.get("report_template"):
            inputs["_report_template_path"] = str(_write_temp_text(rt, ".tmpl"))

        # Route by mode
        try:
            if mode == "github":
                await _run_github(inputs, config_path)
            elif mode == "global_github":
                await _run_global_github(inputs, config_path)
            elif mode == "git":
                await _run_git(inputs, config_path)
            elif mode == "s3":
                await _run_s3(inputs, config_path)
            elif mode == "dir":
                await _run_dir(inputs, config_path)
            elif mode == "stdin":
                await _run_stdin(inputs, config_path)
            else:
                await Actor.fail(status_message=f"unknown mode: {mode!r}")
                return
        finally:
            if config_path:
                config_path.unlink(missing_ok=True)


def _apply_baseline_arg(cmd: list[str], inputs: dict) -> None:
    if bp := inputs.get("_baseline_path"):
        cmd += ["--baseline-path", bp]


def _emit_findings(report_path: Path) -> list[dict]:
    if not report_path.exists():
        return []
    try:
        raw = json.loads(report_path.read_text() or "[]")
    except json.JSONDecodeError as exc:
        log.error("invalid JSON report: %s", exc)
        return []
    return raw if isinstance(raw, list) else []


def _log_proc_output(proc: subprocess.CompletedProcess, tag: str = "bl") -> None:
    if proc.stdout:
        for line in proc.stdout.splitlines()[-50:]:
            Actor.log.info("[%s] %s", tag, line)
    if proc.stderr:
        for line in proc.stderr.splitlines()[-50:]:
            Actor.log.info("[%s-err] %s", tag, line)


async def _push_and_charge(findings: list[dict], source_label: str | None = None) -> int:
    n = 0
    for f in findings:
        if source_label:
            f["_source"] = source_label
        await Actor.push_data(f)
        try:
            await Actor.charge("per_finding")
        except Exception:
            pass
        # Premium charge: only when validation confirmed the secret is LIVE.
        if (f.get("ValidationStatus") or "").lower() == "valid":
            try:
                await Actor.charge("per_validated_live")
            except Exception:
                pass
        n += 1
    return n


async def _charge_per_repo_scanned(n: int = 1) -> None:
    """Charge per_repo_scanned event. Used by single-target modes (github/git)."""
    for _ in range(n):
        try:
            await Actor.charge("per_repo_scanned")
        except Exception:
            pass


# ── Mode handlers ──────────────────────────────────────────────────────────


async def _run_github(inputs: dict, config_path: Path | None) -> None:
    target = inputs.get("target_url")
    if not target:
        await Actor.fail(status_message="target_url is required for github mode")
        return
    report_path = Path(tempfile.mkdtemp(prefix="bl-")) / "report.json"
    cmd = build_github_cmd(inputs, target, report_path, config_path)
    _apply_baseline_arg(cmd, inputs)
    Actor.log.info("cmd: %s", _redact_cmd_for_log(cmd))
    try:
        proc = run_betterleaks(cmd, timeout=REPORT_TIMEOUT)
    except subprocess.TimeoutExpired:
        await Actor.fail(status_message=f"scan exceeded {REPORT_TIMEOUT}s timeout")
        return
    _log_proc_output(proc)
    if proc.returncode == 126:
        await Actor.fail(status_message=f"bad flag: {proc.stderr.strip()[:300]}")
        return
    if proc.returncode not in (0, 1):
        await Actor.fail(status_message=f"betterleaks exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return
    findings = _emit_findings(report_path)
    # Count distinct repos scanned from the betterleaks log; charge per repo.
    scanned_repos = _count_repos_scanned_in_log(proc)
    await _charge_per_repo_scanned(max(1, scanned_repos))
    pushed = await _push_and_charge(findings)
    Actor.log.info("done. repos_scanned=%d findings=%d", scanned_repos, pushed)


def _count_repos_scanned_in_log(proc: subprocess.CompletedProcess) -> int:
    """Parse betterleaks output to count distinct repos scanned.

    Betterleaks logs 'INF scanning repo=<name>' for each repo when scanning
    an org/user URL. For single-repo URLs there's exactly one such line.
    """
    seen = set()
    for stream in (proc.stdout or "", proc.stderr or ""):
        for line in stream.splitlines():
            if "scanning repo=" in line:
                # Format: "INF scanning repo=foo/bar resource=repos"
                try:
                    repo = line.split("scanning repo=", 1)[1].split()[0]
                    seen.add(repo)
                except Exception:
                    continue
    return len(seen)


async def _run_git(inputs: dict, config_path: Path | None) -> None:
    target = inputs.get("target_url")
    if not target:
        await Actor.fail(status_message="target_url (clone URL) is required for git mode")
        return
    report_path = Path(tempfile.mkdtemp(prefix="bl-")) / "report.json"
    # git mode requires the repo to be cloned first
    work = Path(tempfile.mkdtemp(prefix="bl-git-"))
    try:
        clone_proc = subprocess.run(
            ["git", "clone", "--quiet", "--no-single-branch", target, str(work / "repo")],
            capture_output=True, text=True, timeout=300,
        )
        if clone_proc.returncode != 0:
            await Actor.fail(status_message=f"clone failed: {clone_proc.stderr.strip()[:300]}")
            return
        cmd = build_git_cmd(inputs, str(work / "repo"), report_path, config_path)
        _apply_baseline_arg(cmd, inputs)
        Actor.log.info("cmd: %s", _redact_cmd_for_log(cmd))
        try:
            proc = run_betterleaks(cmd, timeout=REPORT_TIMEOUT)
        except subprocess.TimeoutExpired:
            await Actor.fail(status_message=f"scan exceeded {REPORT_TIMEOUT}s timeout")
            return
        _log_proc_output(proc)
        if proc.returncode == 126:
            await Actor.fail(status_message=f"bad flag: {proc.stderr.strip()[:300]}")
            return
        if proc.returncode not in (0, 1):
            await Actor.fail(status_message=f"betterleaks exited {proc.returncode}: {proc.stderr.strip()[:300]}")
            return
        findings = _emit_findings(report_path)
        # git mode = exactly 1 repo scanned.
        await _charge_per_repo_scanned(1)
        pushed = await _push_and_charge(findings)
        Actor.log.info("done. findings=%d", pushed)
    finally:
        shutil.rmtree(work, ignore_errors=True)


async def _run_s3(inputs: dict, config_path: Path | None) -> None:
    target = inputs.get("target_url")
    if not target:
        await Actor.fail(status_message="target_url is required for s3 mode")
        return
    report_path = Path(tempfile.mkdtemp(prefix="bl-")) / "report.json"
    cmd = build_s3_cmd(inputs, target, report_path, config_path)
    _apply_baseline_arg(cmd, inputs)
    Actor.log.info("cmd: %s", _redact_cmd_for_log(cmd))
    try:
        proc = run_betterleaks(cmd, timeout=REPORT_TIMEOUT)
    except subprocess.TimeoutExpired:
        await Actor.fail(status_message=f"scan exceeded {REPORT_TIMEOUT}s timeout")
        return
    _log_proc_output(proc)
    if proc.returncode == 126:
        await Actor.fail(status_message=f"bad flag: {proc.stderr.strip()[:300]}")
        return
    if proc.returncode not in (0, 1):
        await Actor.fail(status_message=f"betterleaks exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return
    findings = _emit_findings(report_path)
    pushed = await _push_and_charge(findings)
    Actor.log.info("done. findings=%d", pushed)


async def _run_dir(inputs: dict, config_path: Path | None) -> None:
    src_url = inputs.get("dir_source_url")
    if not src_url:
        await Actor.fail(status_message="dir_source_url is required for dir mode")
        return
    work_dir = Path(tempfile.mkdtemp(prefix="bl-dir-"))
    try:
        Actor.log.info("downloading archive from %s", src_url)
        suffix = ".zip" if src_url.lower().endswith(".zip") else ".tar.gz"
        archive = _download_to_temp(src_url, suffix=suffix)
        extract_dir = work_dir / "extracted"
        extract_dir.mkdir()
        Actor.log.info("extracting to %s", extract_dir)
        _extract_archive(archive, extract_dir)
        archive.unlink(missing_ok=True)
        report_path = work_dir / "report.json"
        cmd = build_dir_cmd(inputs, extract_dir, report_path, config_path)
        _apply_baseline_arg(cmd, inputs)
        Actor.log.info("cmd: %s", _redact_cmd_for_log(cmd))
        try:
            proc = run_betterleaks(cmd, timeout=REPORT_TIMEOUT)
        except subprocess.TimeoutExpired:
            await Actor.fail(status_message=f"scan exceeded {REPORT_TIMEOUT}s timeout")
            return
        _log_proc_output(proc)
        if proc.returncode == 126:
            await Actor.fail(status_message=f"bad flag: {proc.stderr.strip()[:300]}")
            return
        if proc.returncode not in (0, 1):
            await Actor.fail(status_message=f"betterleaks exited {proc.returncode}: {proc.stderr.strip()[:300]}")
            return
        findings = _emit_findings(report_path)
        pushed = await _push_and_charge(findings)
        Actor.log.info("done. findings=%d", pushed)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


async def _run_stdin(inputs: dict, config_path: Path | None) -> None:
    content = inputs.get("stdin_content")
    if not content:
        await Actor.fail(status_message="stdin_content is required for stdin mode")
        return
    report_path = Path(tempfile.mkdtemp(prefix="bl-")) / "report.json"
    cmd = build_stdin_cmd(inputs, report_path, config_path)
    _apply_baseline_arg(cmd, inputs)
    Actor.log.info("cmd: %s", _redact_cmd_for_log(cmd))
    try:
        proc = run_betterleaks(cmd, stdin_input=content, timeout=REPORT_TIMEOUT)
    except subprocess.TimeoutExpired:
        await Actor.fail(status_message=f"scan exceeded {REPORT_TIMEOUT}s timeout")
        return
    _log_proc_output(proc)
    if proc.returncode == 126:
        await Actor.fail(status_message=f"bad flag: {proc.stderr.strip()[:300]}")
        return
    if proc.returncode not in (0, 1):
        await Actor.fail(status_message=f"betterleaks exited {proc.returncode}: {proc.stderr.strip()[:300]}")
        return
    findings = _emit_findings(report_path)
    pushed = await _push_and_charge(findings)
    Actor.log.info("done. findings=%d", pushed)


async def _run_global_github(inputs: dict, config_path: Path | None) -> None:
    """Our addition: GitHub Code Search picks unique repos, parallel `betterleaks git` against each."""
    query = inputs.get("global_search_query")
    if not query:
        await Actor.fail(status_message="global_search_query is required for global_github mode")
        return
    pat = inputs.get("github_token")
    if not pat:
        await Actor.fail(status_message="github_token is required for global_github mode (Code Search is auth-only)")
        return
    max_repos = int(inputs.get("global_max_repos", 25))

    # Stage 1: discover unique repos via Code Search
    Actor.log.info("global_github: searching code for query=%r (max_repos=%d)", query, max_repos)
    try:
        clone_urls = discover_unique_repos(pat, query, max_repos)
    except CodeSearchError as exc:
        await Actor.fail(status_message=f"code search failed: {exc}")
        return
    Actor.log.info("discovered %d unique repos to scan", len(clone_urls))
    if not clone_urls:
        Actor.log.warning("no repos matched the query")
        return

    try:
        await Actor.charge("per_code_search_query")
    except Exception:
        pass

    # Stage 2: parallel scan each repo
    sem = asyncio.Semaphore(MAX_PARALLEL_GLOBAL)
    total_pushed = 0
    completed_lock = asyncio.Lock()
    scanned = 0

    async def scan_one(clone_url: str) -> None:
        nonlocal total_pushed, scanned
        async with sem:
            work = Path(tempfile.mkdtemp(prefix="bl-glob-"))
            try:
                repo_path = work / "repo"
                clone_proc = await asyncio.to_thread(
                    subprocess.run,
                    ["git", "clone", "--quiet", "--no-single-branch", clone_url, str(repo_path)],
                    capture_output=True, text=True, timeout=300,
                )
                if clone_proc.returncode != 0:
                    Actor.log.warning("skip %s: clone failed", clone_url)
                    return
                report_path = work / "report.json"
                cmd = build_git_cmd(inputs, str(repo_path), report_path, config_path)
                _apply_baseline_arg(cmd, inputs)
                try:
                    proc = await asyncio.to_thread(
                        run_betterleaks, cmd, None, GLOBAL_PER_REPO_TIMEOUT,
                    )
                except subprocess.TimeoutExpired:
                    Actor.log.warning("skip %s: scan timeout", clone_url)
                    return
                if proc.returncode not in (0, 1):
                    Actor.log.warning("skip %s: betterleaks exit %d", clone_url, proc.returncode)
                    return
                findings = _emit_findings(report_path)
                async with completed_lock:
                    pushed = await _push_and_charge(findings, source_label=clone_url)
                    total_pushed += pushed
                    scanned += 1
                    try:
                        await Actor.charge("per_repo_scanned")
                    except Exception:
                        pass
                    Actor.log.info("[%d/%d] %s -> %d findings", scanned, len(clone_urls), clone_url, pushed)
            finally:
                shutil.rmtree(work, ignore_errors=True)

    tasks = [scan_one(u) for u in clone_urls]
    await asyncio.gather(*tasks)
    Actor.log.info("global_github done. scanned=%d/%d findings=%d", scanned, len(clone_urls), total_pushed)


if __name__ == "__main__":
    asyncio.run(main())
