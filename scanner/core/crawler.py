"""Web crawler — discovers endpoints, forms, input parameters, and JS API routes."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Any

import httpx
from bs4 import BeautifulSoup

from scanner.utils.logger import get_logger

log = get_logger("crawler")


class CrawlResult:
    """Holds everything the crawler discovered."""

    def __init__(self) -> None:
        self.endpoints: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.parameters: set[str] = set()
        self.js_api_endpoints: list[str] = []
        self.authenticated_pages: list[str] = []

    def summary(self) -> dict[str, int]:
        return {
            "endpoints_found": len(self.endpoints),
            "forms_discovered": len(self.forms),
            "input_parameters": len(self.parameters),
            "js_api_endpoints": len(self.js_api_endpoints),
            "authenticated_pages": len(self.authenticated_pages),
        }


def _is_same_origin(base: str, url: str) -> bool:
    return urlparse(base).netloc == urlparse(url).netloc


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        action_url = urljoin(page_url, action) if action else page_url
        inputs: list[dict[str, str]] = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append({
            "action": action_url,
            "method": method,
            "inputs": inputs,
        })
    return forms


# Regex to pull API-like paths from inline JS
_JS_API_RE = re.compile(
    r"""(?:fetch|axios\.\w+|XMLHttpRequest\.open)\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_JS_PATH_RE = re.compile(r"""['"](/api/[^'"]+)['"]""")


def _extract_js_endpoints(body: str, base_url: str) -> list[str]:
    found: list[str] = []
    for match in _JS_API_RE.finditer(body):
        path = match.group(1)
        found.append(urljoin(base_url, path))
    for match in _JS_PATH_RE.finditer(body):
        found.append(urljoin(base_url, match.group(1)))
    return list(set(found))


def crawl(
    base_url: str,
    max_depth: int = 3,
    max_pages: int = 200,
    cookie: str | None = None,
    timeout: float = 10.0,
    respect_robots: bool = True,
) -> CrawlResult:
    """Crawl *base_url* up to *max_depth* levels, collecting endpoints and forms."""
    log.info("=== STAGE 04: Web Crawler — %s ===", base_url)

    result = CrawlResult()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(base_url, 0)]

    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    disallowed: set[str] = set()
    if respect_robots:
        disallowed = _fetch_robots_disallow(base_url, headers, timeout)

    with httpx.Client(
        verify=False,
        timeout=timeout,
        follow_redirects=True,
        headers=headers,
    ) as client:
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)

            normalized = urlparse(url)._replace(fragment="").geturl()
            if normalized in visited:
                continue
            if not _is_same_origin(base_url, normalized):
                continue
            if respect_robots and any(normalized.startswith(d) for d in disallowed):
                continue

            visited.add(normalized)
            result.endpoints.append(normalized)

            # Collect query-string parameter names
            for param in parse_qs(urlparse(normalized).query):
                result.parameters.add(param)

            try:
                resp = client.get(normalized)
            except httpx.HTTPError as exc:
                log.debug("Failed to fetch %s: %s", normalized, exc)
                continue

            # Detect pages that required authentication (redirected to login, 401/403)
            if resp.status_code in (401, 403):
                result.authenticated_pages.append(normalized)
                continue

            content_type = resp.headers.get("content-type", "")
            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Forms
            forms = _extract_forms(soup, normalized)
            result.forms.extend(forms)
            for form in forms:
                for inp in form["inputs"]:
                    if inp["name"]:
                        result.parameters.add(inp["name"])

            # JS endpoints
            result.js_api_endpoints.extend(
                _extract_js_endpoints(resp.text, normalized)
            )

            # Enqueue discovered links
            if depth < max_depth:
                for tag in soup.find_all("a", href=True):
                    href = urljoin(normalized, tag["href"])
                    queue.append((href, depth + 1))

    # Deduplicate JS endpoints
    result.js_api_endpoints = list(set(result.js_api_endpoints))

    summary = result.summary()
    log.info(
        "Crawl complete — Endpoints: %d | Forms: %d | Params: %d | JS APIs: %d | Auth pages: %d",
        summary["endpoints_found"],
        summary["forms_discovered"],
        summary["input_parameters"],
        summary["js_api_endpoints"],
        summary["authenticated_pages"],
    )
    return result


def _fetch_robots_disallow(
    base_url: str, headers: dict[str, str], timeout: float
) -> set[str]:
    """Parse robots.txt and return a set of absolute disallowed paths."""
    robots_url = urljoin(base_url, "/robots.txt")
    disallowed: set[str] = set()
    try:
        with httpx.Client(verify=False, timeout=timeout, headers=headers) as client:
            resp = client.get(robots_url)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.add(urljoin(base_url, path))
    except httpx.HTTPError:
        pass
    return disallowed
