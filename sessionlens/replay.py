"""Re-send a captured request from Python, optionally dropping headers/cookies, to learn what the server checks.

Note: the server sees Python's TLS fingerprint, not Chrome's. Bot protection (Cloudflare) may reject
replays that work in the browser; that difference is itself worth learning from.
"""

import time
from dataclasses import dataclass
from typing import Any

import httpx2

from sessionlens.cookies import parse_cookie_header

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SKIP_HEADERS = {"host", "content-length", "connection", "transfer-encoding", "keep-alive", "accept-encoding"}
_MAX_TRIES = 80
_PREVIEW_CHARS = 2000


@dataclass
class Captured:
    method: str
    url: str
    headers: list[list[str]]
    body: bytes


@dataclass
class Result:
    status: int
    size: int
    preview: str
    headers: list[list[str]]
    elapsed_ms: float

    def json(self) -> dict[str, Any]:
        return {"status": self.status, "size": self.size, "preview": self.preview, "headers": self.headers,
                "elapsedMs": self.elapsed_ms}  # fmt: skip


def similar(a: Result, b: Result) -> bool:
    """Same status and roughly the same body size counts as 'the server didn't care'."""
    return a.status == b.status and abs(a.size - b.size) <= max(50, 0.05 * a.size)


def _prepare(req: Captured, drop_headers: set[str], drop_cookies: set[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for name, value in req.headers:
        lower = name.lower()
        if lower in _SKIP_HEADERS or lower in drop_headers or lower.startswith(":"):
            continue
        if lower == "cookie":
            kept = [f"{n}={v}" if n else v for n, v in parse_cookie_header(value) if n not in drop_cookies]
            if not kept:
                continue
            value = "; ".join(kept)
        headers[lower] = value
    return headers


class Replayer:
    def __init__(self, client: httpx2.Client | None = None) -> None:
        self.client = client or httpx2.Client(follow_redirects=False, timeout=15)

    def send(self, req: Captured, drop_headers: set[str] | None = None, drop_cookies: set[str] | None = None,
             allow_unsafe: bool = False) -> Result:  # fmt: skip
        if req.method.upper() not in SAFE_METHODS and not allow_unsafe:
            raise PermissionError(f"{req.method} could repeat an action (order, payment, post). Confirm to replay it.")
        headers = _prepare(req, drop_headers or set(), drop_cookies or set())
        started = time.perf_counter()
        response = self.client.request(req.method, req.url, headers=headers, content=req.body or None)
        return Result(
            status=response.status_code,
            size=len(response.content),
            preview=response.text[:_PREVIEW_CHARS],
            headers=[[k, v] for k, v in response.headers.items()],
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

    def minimize(self, req: Captured, allow_unsafe: bool = False) -> dict[str, Any]:
        """Drop one header / cookie at a time; keep it dropped if the response stays the same."""
        baseline = self.send(req, allow_unsafe=allow_unsafe)
        header_names = sorted({n.lower() for n, _ in req.headers} - _SKIP_HEADERS - {"cookie"})
        cookie_names = sorted({n for name, value in req.headers if name.lower() == "cookie"
                               for n, _ in parse_cookie_header(value) if n})  # fmt: skip
        dropped_headers: set[str] = set()
        dropped_cookies: set[str] = set()
        tries = 0
        for name in header_names:
            if tries >= _MAX_TRIES:
                break
            tries += 1
            if similar(baseline, self.send(req, dropped_headers | {name}, dropped_cookies, allow_unsafe)):
                dropped_headers.add(name)
        for name in cookie_names:
            if tries >= _MAX_TRIES:
                break
            tries += 1
            if similar(baseline, self.send(req, dropped_headers, dropped_cookies | {name}, allow_unsafe)):
                dropped_cookies.add(name)
        return {
            "baseline": baseline.json(),
            "requiredHeaders": [h for h in header_names if h not in dropped_headers],
            "requiredCookies": [c for c in cookie_names if c not in dropped_cookies],
            "unneededHeaders": sorted(dropped_headers),
            "unneededCookies": sorted(dropped_cookies),
            "tries": tries + 1,
            "complete": tries < _MAX_TRIES,
        }
