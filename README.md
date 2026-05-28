# Betterleaks Cloud - GitHub & S3 Secret Scanner

Cloud-hosted [Betterleaks](https://github.com/betterleaks/betterleaks) v1.3.1 for hunting leaked API keys, wallet private keys, and credentials anywhere on GitHub, in cloned git repos, or in S3 / R2 / MinIO buckets. Optional live validation probes each detected secret against the vendor API to flag which ones are still active.

Available as an [Apify Actor](https://apify.com/anshumanatrey/betterleaks-cloud). $0.05 start + $0.05 per repo scanned + $0.30 per live-validated key. No install, no CLI, flat JSON output.

---

## What does it do?

Scans a GitHub org, user, repo, pull request, issue, gist, action workflow, or S3 bucket for leaked credentials. Built on Betterleaks (the Gitleaks successor, maintained by the original Gitleaks author Zachary Rice + co-maintainers from Red Hat, Amazon, RBC). Every Betterleaks CLI flag is exposed as an input field. When you enable validation, each finding is probed live against the vendor API and tagged `valid`, `invalid`, `revoked`, `unknown`, or `error`.

## How is it different from running Betterleaks locally?

| | Local Betterleaks CLI | This actor |
|---|---|---|
| Setup | Install Go binary, set up GitHub token, configure shell | Paste a JSON input |
| Scope | One target at a time | github / git / s3 modes + our `global_github` mode (Code Search picks repos) |
| Validation cost | Your machine's HTTP egress | Apify-managed, parallel workers |
| Output handling | stdout JSON, parse yourself | Dataset records, filterable views |
| Schedule | cron + DIY | Apify Schedules built-in |
| Cost | Your laptop's electricity | $0.05 actor start + $0.05 per repo scanned |

## How is it different from our gitleaks-github-secret-scanner actor?

| | gitleaks-cloud | betterleaks-cloud (this) |
|---|---|---|
| Engine | Gitleaks 8.x | Betterleaks 1.3.1 (Gitleaks successor) |
| Live validation | not supported | yes (opt-in) |
| Source types | github + git only | github, git, s3, dir, stdin, global_github |
| Pricing | $0.01 + $0.02 per repo | $0.05 + $0.05 per repo + $0.30 per live-validated key |
| Best for | Volume scanning, low cost per scan | Premium scans where "is the secret still live?" matters |

## When should I use it?

- Auditing your own GitHub org for secrets that slipped into commits
- Bug bounty hunting where you want to validate keys live before reporting
- Pre-acquisition security check on a target company's GitHub footprint
- Continuous monitoring on a schedule, alerting on any new live-validated finding
- Forensics: tracing which dangling commit on which PR ref leaked a credential
- Scanning a Cloudflare R2 / AWS S3 bucket someone shared publicly

## What does it cost?

Pay-per-event:
- $0.05 per actor start
- $0.05 per repo scanned (in github / git / global_github modes)
- $0.01 per finding pushed to the dataset
- $0.30 per **live-validated** secret (only when validation is on AND status returns `valid`)
- $0.005 per Code Search query (only in `global_github` mode)

Typical scans:

| Scenario | Cost |
|---|---|
| Scan 1 small repo, 1 finding, no validation | $0.11 |
| Scan 1 big repo, 30 findings, no validation | $0.40 |
| Scan an org with 25 repos, 50 findings, no validation | $1.80 |
| 25-repo global search for `rzp_live_` | $1.93 |
| 100-repo scan, 200 findings, 10 live-validated | $10.05 |

Compare to GitGuardian Enterprise at ~$5000/year flat. Per-comprehensive-scan with this actor is 300-500x cheaper.

## Which modes can I scan in?

| Mode | What it scans | Required input |
|---|---|---|
| `github` | A specific GitHub org / user / repo / PR / issue / gist (you choose) | `target_url`, `github_token` recommended |
| `global_github` | All of GitHub by keyword - we add this layer via Code Search | `global_search_query`, `github_token` required |
| `git` | A single git clone URL with full history | `target_url` |
| `s3` | AWS S3, Cloudflare R2, MinIO, or any S3-compatible bucket | `target_url`, S3 creds (or `s3_anonymous` for public) |
| `dir` | A tarball / zip URL - we download, extract, scan filesystem | `dir_source_url` |
| `stdin` | Raw text content you paste in | `stdin_content` |

## Which GitHub resources can it scan in `github` mode?

All 12 surfaces betterleaks supports, selectable via `include` / `exclude`:

- `repos` (default), `forks`
- `prs`, `pr-comments`
- `issues`, `issue-comments`
- `actions`, `action-artifacts`
- `discussions`
- `releases`, `release-assets`
- `gists`

You can also filter by `since` / `until` dates, exclude repos by glob pattern, or target specific GitHub Actions workflow files.

## Does it find leaks that were deleted from current files?

Yes. Betterleaks scans the full git history. A secret that was committed and then deleted in a later commit still appears in the history and gets detected. The `Commit` field on each finding tells you which commit introduced the leak.

You can also enable advanced `--log-opts` pass-through to use git pickaxe (`-S secret_string`) for targeted historical searches.

## Is the secret validated against the live vendor API?

Optional - off by default to keep scans fast. Set `validation: true` and Betterleaks fires HTTP requests against the vendor API for each finding using the rule's built-in CEL validator.

Output fields:
- `ValidationStatus`: `valid` (still active), `invalid` (rejected), `revoked` (explicitly disabled), `unknown` (couldn't determine), or `error`
- `ValidationReason`: human-readable why
- `ValidationMeta`: vendor-specific metadata. For a GitHub PAT, this includes `username`, `name`, and granted `scopes`. For Stripe, the test/live mode + account info.

Note: validation only fires for rules that ship with a `validate` CEL clause in their TOML. Not every detected secret type has one (the upstream rule set is expanding over time).

You can also tune validation behavior:
- `validation_timeout` (per-request HTTP timeout)
- `validation_workers` (parallel HTTP workers)
- `validation_status` (filter output to only certain statuses)
- `validation_debug` (include raw HTTP response in `ValidationMeta`)
- `validation_extract_empty` (include validator outputs even when empty)
- `validation_env_vars` (expose extra env vars to CEL validators)

## Can I use a custom detection rule?

Yes - paste a full betterleaks TOML config into `custom_config_toml`. Either replaces the built-in rules or adds to them depending on how you write the TOML.

You can also use `enable_rule` to run only a whitelist of rule IDs (e.g. `["github-fine-grained-pat", "stripe-secret-key"]`) from the built-in set without writing your own config.

Reference format: https://github.com/betterleaks/betterleaks/blob/main/.betterleaks.toml

## What does the output look like?

Each dataset record is the raw `Finding` struct from betterleaks - no transformation, no field renaming:

```json
{
  "RuleID": "github-fine-grained-pat",
  "Description": "GitHub Fine-Grained Personal Access Token, risking unauthorized repo access.",
  "Match": "github_pat_11AABBCC...",
  "Secret": "github_pat_11AABBCC...",
  "StartLine": 12,
  "EndLine": 12,
  "StartColumn": 18,
  "EndColumn": 105,
  "MatchContext": "...optional surrounding lines if match_context is set...",
  "CaptureGroups": {},
  "Fragment": {
    "FilePath": "config/secrets.env",
    "Url": "https://github.com/owner/repo/blob/<sha>/config/secrets.env#L12"
  },
  "Attributes": {
    "path": "config/secrets.env",
    "resource": "git.patch_content",
    "url": "https://github.com/owner/repo/blob/<sha>/config/secrets.env#L12",
    "git.author_name": "alice",
    "git.author_email": "alice@example.com",
    "git.commit": "abcd1234",
    "git.date": "2025-06-12T10:23:14Z",
    "git.message": "Add config",
    "github.owner": "owner",
    "github.repo": "repo",
    "github.visibility": "public"
  },
  "Tags": [],
  "Fingerprint": "abcd1234:config/secrets.env:github-fine-grained-pat:12",
  "ValidationStatus": "valid",
  "ValidationReason": "",
  "ValidationMeta": {
    "username": "alice",
    "name": "Alice Doe",
    "scopes": "repo, workflow"
  }
}
```

The dataset has two pre-configured views:
- **Findings**: all records
- **Live secrets only**: filter to `ValidationStatus == valid`, the high-signal triage list

## How accurate is it?

Based on the underlying Betterleaks 1.3.1 rule set (200+ detectors), plus the upstream's BPE-tokenization based false-positive filter and CEL-based contextual filters. Compute usage observed in real test runs:

- Single small repo scan: ~7 seconds, 0.0084 compute units
- Scan of `anshumanatrey/*` (~30 repos): ~134 seconds, 0.1491 compute units, 735 findings
- 3-repo `global_github` scan with query `rzp_live_`: ~8.5 seconds, 0.0095 compute units, 14 findings

## Common questions

**Q: Can I scan a private repo?** Yes - provide a `github_token` with `repo` scope.

**Q: Does it scan PR branches and dangling commits?** PR refs yes via `--include prs`. Dangling commits aren't currently exposed but the underlying tool supports it.

**Q: How does it handle rate limits?** Without a `github_token`, GitHub limits to ~60 req/hr shared. With a token: 5000 req/hr on your account. Always provide a token for any real scan.

**Q: Can I run it on a schedule?** Yes via Apify Schedules. Recommended for continuous monitoring use cases.

**Q: Can I use my own betterleaks rule TOML?** Yes via `custom_config_toml`. Or whitelist specific built-in rules via `enable_rule`.

**Q: What's `global_github` mode?** Our addition on top of upstream betterleaks. You provide a search query, we use GitHub Code Search to find unique candidate repos, then run `betterleaks git` against each in parallel. Useful for hunting a specific secret pattern across all of GitHub.

**Q: Why not use the cheaper gitleaks-github-secret-scanner actor instead?** Use that one for high-volume cost-sensitive scans. Use this one when live validation matters (bug bounty triage, incident response, knowing which secrets to actually rotate).

**Q: What happens to detected secrets?** Written to the run's dataset, accessible only to the user who ran the actor. We never store them server-side.

**Q: Can I scan an S3 bucket I don't own?** Only if it's public (anonymous mode) or you have credentials.

**Q: What's the maximum scan size?** No hard cap on repos. `max_target_megabytes` (default 100) skips files larger than that.

## Limitations

- Per-CEL-rule validation: only rules with a `validate` clause actually probe live. Not every secret type has one yet.
- `global_github` mode requires a GitHub PAT (Code Search is auth-only).
- `dir` mode requires the source to be a downloadable tarball URL, not a local file.
- Apify run timeout caps individual scans at 30 minutes per subprocess. For org scans larger than 200 repos, split into multiple runs.
- The `stdin` mode is limited by Apify's input size cap (~5 MB).

## Ethical use

For authorized security testing only. This actor scans public GitHub content (the same content any logged-in GitHub user can see), or private repos that your PAT explicitly grants access to.

Findings should be reported through responsible disclosure channels:
- The leaking developer (commit author email)
- The vendor's `security@` address
- A bug-bounty program if one exists for the vendor

Using leaked credentials without owner authorization is illegal in most jurisdictions.

## Other actors in my portfolio

- [gitleaks-github-secret-scanner](https://github.com/AnshumanAtrey/gitleaks-github-secret-scanner) - the cheaper Gitleaks-based scanner without validation
- [holehe-email-osint](https://github.com/AnshumanAtrey/holehe-email-osint) - email to registered accounts (120+ sites)
- [phoneinfoga-phone-osint](https://github.com/AnshumanAtrey/phoneinfoga-phone-osint) - phone OSINT
- [theharvester-osint](https://github.com/AnshumanAtrey/theharvester-osint) - emails / subdomains / hosts via public sources
- [social-analyzer](https://github.com/AnshumanAtrey/social-analyzer) - username across 300+ social platforms
- [nmap-scanner](https://github.com/AnshumanAtrey/nmap-scanner) - Nmap port scanner
- [netintel](https://github.com/AnshumanAtrey/netintel) - DNS / WHOIS / IP geo / port scan / SSL / tech stack
- [instagram-profile-intel-no-login](https://github.com/AnshumanAtrey/instagram-profile-intel-no-login) - Instagram profile intel without login
- [bug-bounty-finder](https://github.com/AnshumanAtrey/bug-bounty-finder) - search HackerOne, Bugcrowd, Intigriti

## License

MIT. The upstream Betterleaks binary is also MIT, maintained by [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks) (Zachary Rice and co-maintainers from Red Hat, Amazon, RBC).
