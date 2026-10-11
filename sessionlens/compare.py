"""Compare two sessions, e.g. the same login flow captured on different days or browsers."""

from typing import Any
from urllib.parse import urlsplit

Json = dict[str, Any]


def _cookie_keys(model: Json) -> set[str]:
    return {f"{r['domain']} {r['name']}" for r in model["rows"] if r["group"] == "cookie"}


def _endpoints(model: Json) -> set[str]:
    out = set()
    for r in model["requests"]:
        if r.get("match") == "wire-only":  # Chrome background or other apps: not part of the site's flow
            continue
        parts = urlsplit(r["url"])
        out.add(f"{r['method']} {parts.hostname}{parts.path}")
    return out


def compare(a: Json, b: Json) -> Json:
    def split(x: set[str], y: set[str]) -> Json:
        return {"onlyA": sorted(x - y), "onlyB": sorted(y - x), "both": sorted(x & y)}

    return {
        "cookies": split(_cookie_keys(a), _cookie_keys(b)),
        "endpoints": split(_endpoints(a), _endpoints(b)),
        "blocked": {"a": len(a["blocked"]), "b": len(b["blocked"])},
        "steps": {"a": [s["label"] for s in a["steps"]], "b": [s["label"] for s in b["steps"]]},
    }
