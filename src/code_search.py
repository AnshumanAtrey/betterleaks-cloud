"""GitHub Code Search repo discovery — for global_github mode.

Betterleaks itself has no "scan all of GitHub" mode. To approximate it we
search GitHub Code Search for files matching the user's keyword/pattern,
dedupe to unique repos, then run betterleaks against each. Requires a PAT
because GitHub Code Search is auth-only.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Iterator

import requests

GITHUB_API = "https://api.github.com"
log = logging.getLogger(__name__)


class CodeSearchError(Exception):
    pass


@dataclass
class CodeSearchHit:
    repo_full_name: str
    repo_url: str
    path: str
    sha: str
    html_url: str
    default_branch: str = "main"


class CodeSearchClient:
    def __init__(self, pat: str):
        if not pat:
            raise ValueError("GitHub Code Search requires a PAT")
        self.pat = pat
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "betterleaks-cloud-actor/0.2",
        })

    def search(self, query: str, max_results: int = 100) -> Iterator[CodeSearchHit]:
        per_page = min(100, max(1, max_results))
        page = 1
        returned = 0
        while returned < max_results and page <= 10:
            r = self._get_with_retry(
                f"{GITHUB_API}/search/code",
                {"q": query, "per_page": per_page, "page": page},
            )
            data = r.json()
            items = data.get("items", [])
            if not items:
                return
            for item in items:
                repo = item.get("repository", {})
                yield CodeSearchHit(
                    repo_full_name=repo.get("full_name", ""),
                    repo_url=repo.get("html_url", ""),
                    path=item.get("path", ""),
                    sha=item.get("sha", ""),
                    html_url=item.get("html_url", ""),
                    default_branch=repo.get("default_branch", "main"),
                )
                returned += 1
                if returned >= max_results:
                    return
            if len(items) < per_page:
                return
            page += 1

    def _get_with_retry(self, url, params, retries=2):
        for attempt in range(retries + 1):
            r = self.session.get(url, params=params, timeout=30)
            if r.status_code == 200:
                return r
            body_lower = r.text.lower()
            if r.status_code == 401:
                raise CodeSearchError("GitHub rejected the PAT (401). Regenerate at github.com/settings/tokens.")
            if r.status_code in (403, 429) and (
                "rate limit" in body_lower
                or "secondary rate" in body_lower
                or r.headers.get("X-RateLimit-Remaining") == "0"
            ):
                reset = r.headers.get("X-RateLimit-Reset")
                wait = max(0, int(reset) - int(time.time())) + 1 if reset else 30
                if wait <= 120 and attempt < retries:
                    log.warning("rate-limit; sleeping %ds", wait)
                    time.sleep(wait)
                    continue
                raise CodeSearchError(f"GitHub Code Search rate limit hit. Wait {wait}s and retry.")
            if r.status_code == 422:
                raise CodeSearchError(f"Bad query (422): {r.text[:200]}")
            if r.status_code == 404:
                raise CodeSearchError(f"Endpoint 404: {url}")
            if r.status_code >= 500 and attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise CodeSearchError(f"Code Search returned {r.status_code}: {r.text[:300]}")
        raise CodeSearchError("retries exhausted")


def discover_unique_repos(
    pat: str,
    query: str,
    max_repos: int,
) -> list[str]:
    """Return clone URLs for unique repos containing the query. Up to max_repos."""
    client = CodeSearchClient(pat)
    unique: dict[str, str] = {}
    for hit in client.search(query, max_results=max_repos * 4):
        if hit.repo_full_name in unique:
            continue
        unique[hit.repo_full_name] = hit.repo_url + ".git"
        if len(unique) >= max_repos:
            break
    return list(unique.values())
