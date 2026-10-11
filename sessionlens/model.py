"""Turn the raw event log into the analyzer's view: steps, state rows, requests, lineage.

Pure function of the events (no I/O), so live sessions and saved sessions render the same way.
"""

import base64
import bisect
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from sessionlens.bodies import decompress, describe, describe_form_data
from sessionlens.cookies import (
    SetCookie,
    blocked_reason,
    domain_matches,
    parse_cookie_header,
    parse_set_cookie,
    path_matches,
)
from sessionlens.replay import Captured

Json = dict[str, Any]

MERGE_NAV_MS = 2500  # a navigation this soon after an action belongs to that action's step
NAV_LOOKBACK_MS = 10_000  # how far back a navigation's main-frame request may have started
MATCH_WINDOW_MS = (-1000, 5000)  # wire request time minus webRequest start time
AMBIGUOUS_MS = 50
LINEAGE_BEFORE_MS = 3000  # a jar change can follow its Set-Cookie response by up to this much
LINEAGE_AFTER_MS = 500
DISK_FLUSH_MS = 30_000

# Hosts Chrome itself talks to (updates, variations, safe browsing). webRequest never sees these.
_BROWSER_HOSTS = ("googleapis.com", "gstatic.com", "googleusercontent.com", "gvt1.com", "google.com")

_NAV_LABELS = {
    "typed": "typed URL", "link": "followed link", "reload": "reload", "form_submit": "form submit",
    "start_page": "start page", "generated": "omnibox search", "auto_bookmark": "bookmark", "keyword": "search",
}  # fmt: skip

_DISK_LABELS = {
    "files": "Files changed", "cookies_db": "Cookie DB writes", "cache": "Cache entries", "history": "History",
    "hsts": "HSTS (force HTTPS)", "network": "Network state", "prefs": "Preferences",
    "indexeddb": "IndexedDB", "serviceworker": "Service workers",
}  # fmt: skip


# sessionlens's own pages (the capture window's start page) are not part of the browsing.
_OWN_PAGES = "http://127.0.0.1:8765/"


def _exchange_id(event: Json) -> str:
    """One wire request/response pair: connection + stream."""
    return f"w-{str(event['conn']).replace(':', '')}-{event['stream']}"


def prune_unmatched_wire(events: list[Json]) -> list[Json]:
    """Keep only wire data that belongs to a request the browser made (seen by the extension).

    Drops other apps on the Mac (Spotify, Chromecast, local servers), Chrome's own background calls, and
    live wire events superseded by the final re-decode. Result is time-ordered.
    """
    analysis = Analysis(events)
    keep = {ex.id for ex in analysis.exchanges.values() if ex.matched}
    return [e for e in analysis.events if not e["type"].startswith("wire.") or _exchange_id(e) in keep]


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def _short(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.hostname or ''}{parts.path or '/'}"


def _header(headers: list[list[str]], name: str) -> list[str]:
    return [v for n, v in headers if n.lower() == name]


@dataclass
class Step:
    id: int
    t: float
    kind: str
    label: str
    url: str | None = None
    screenshot: int | None = None
    event: Json | None = field(default=None, repr=False)  # the action that made this step (not sent to the UI)


@dataclass
class Exchange:
    """One request/response pair seen on the wire."""

    id: str
    req: Json | None = None
    resp: Json | None = None
    chunks: dict[str, list[Json]] = field(default_factory=lambda: {"req": [], "resp": []})
    matched: bool = False


@dataclass
class Hop:
    """One URL in a webRequest request (redirects create a new hop with the same requestId)."""

    id: str
    request_id: str
    t: float
    url: str
    method: str
    resource_type: str
    tab: int | None
    frame: int | None
    initiator: str | None
    body: Json | None
    req_headers: list[list[str]] = field(default_factory=list)
    resp_headers: list[list[str]] = field(default_factory=list)
    resp_t: float | None = None
    status: int | None = None
    redirect_to: str | None = None
    from_cache: bool = False
    error: str | None = None
    wire: Exchange | None = None
    match: str = "ext-only"


@dataclass
class Change:
    t: float
    row: str
    present: bool
    value: str | None
    cause: str = ""
    baseline: bool = False
    source: str = ""
    request: str | None = None


@dataclass
class Row:
    id: str
    group: str
    section: str
    name: str
    domain: str = ""
    path: str = "/"
    attrs: Json = field(default_factory=dict)
    changes: list[Change] = field(default_factory=list)
    sent_by: list[str] = field(default_factory=list)
    badges: set[str] = field(default_factory=set)


@dataclass
class Request:
    """What the UI lists: a webRequest hop (maybe matched to the wire) or a wire-only exchange."""

    id: str
    t: float
    url: str
    method: str
    hop: Hop | None
    wire: Exchange | None
    step: int = 0
    cookies_sent: list[str] = field(default_factory=list)
    cookies_set: list[Json] = field(default_factory=list)

    @property
    def req_headers(self) -> list[list[str]]:
        if self.wire and self.wire.req:
            return list(self.wire.req["headers"])
        return self.hop.req_headers if self.hop else []

    @property
    def resp_headers(self) -> list[list[str]]:
        if self.wire and self.wire.resp:
            return list(self.wire.resp["headers"])
        return self.hop.resp_headers if self.hop else []

    @property
    def resp_t(self) -> float | None:
        if self.hop and self.hop.resp_t is not None:
            return self.hop.resp_t
        return self.wire.resp["t"] if self.wire and self.wire.resp else None

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""


class Analysis:
    def __init__(self, events: list[Json]) -> None:
        # After capture, the whole pcap is decoded again with the complete key log ("wire.reset");
        # that pass supersedes live wire events, which miss packets whose keys arrived late.
        reset_at = max((i for i, e in enumerate(events) if e["type"] == "wire.reset"), default=-1)
        kept = [e for i, e in enumerate(events) if i > reset_at or not e["type"].startswith("wire.")]
        self.events = sorted(kept, key=lambda e: e.get("t", 0))
        self.hops: list[Hop] = []
        self.exchanges: dict[str, Exchange] = {}
        self.steps: list[Step] = []
        self.rows: dict[str, Row] = {}
        self.requests: dict[str, Request] = {}
        self.blocked: list[Json] = []
        self.screenshots: list[Json] = [e for e in self.events if e["type"] == "screenshot"]
        self.secret_fields: set[str] = set()
        self.disk_cookies: list[Json] = [e for e in self.events if e["type"] == "disk.cookies"]
        self._build()

    # --- building -------------------------------------------------------------

    def _build(self) -> None:
        self._collect_hops()
        self._collect_wire()
        self._match_wire()
        self._build_steps()
        self._build_requests()
        self._build_cookie_rows()
        self._build_storage_rows()
        self._link_cookies()

    def _collect_hops(self) -> None:
        latest: dict[str, Hop] = {}
        counts: dict[str, int] = {}
        for e in self.events:
            kind = e["type"]
            if kind == "req.start":
                rid = str(e["requestId"])
                n = counts.get(rid, 0)
                counts[rid] = n + 1
                hop = Hop(
                    id=f"e{rid}.{n}", request_id=rid, t=e["t"], url=e["url"], method=e["method"],
                    resource_type=e.get("resourceType", ""), tab=e.get("tabId"), frame=e.get("frameId"),
                    initiator=e.get("initiator"), body=e.get("body"),
                )  # fmt: skip
                latest[rid] = hop
                self.hops.append(hop)
                continue
            hop_or_none = latest.get(str(e.get("requestId"))) if kind.startswith(("req.", "resp.")) else None
            if hop_or_none is None:
                continue
            hop = hop_or_none
            if kind == "req.headers":
                hop.req_headers = [[h["name"], h.get("value", "")] for h in e.get("headers") or []]
            elif kind == "resp.headers":
                hop.resp_headers = [[h["name"], h.get("value", "")] for h in e.get("headers") or []]
                hop.resp_t = e["t"]
                hop.status = e.get("statusCode")
            elif kind == "req.redirect":
                hop.redirect_to = e.get("redirectUrl")
                hop.status = e.get("statusCode")
                hop.from_cache = bool(e.get("fromCache"))
            elif kind == "req.done":
                hop.status = e.get("statusCode", hop.status)
                hop.from_cache = bool(e.get("fromCache"))
            elif kind == "req.error":
                hop.error = e.get("error")

    def _collect_wire(self) -> None:
        for e in self.events:
            if e["type"] == "action" and e.get("action") == "submit":
                for f in e.get("fields") or []:
                    if f.get("type") == "password":
                        self.secret_fields.add(str(f.get("name", "")).lower())
            if e["type"] not in ("wire.msg", "wire.data"):
                continue
            xid = _exchange_id(e)
            ex = self.exchanges.setdefault(xid, Exchange(id=xid))
            if e["type"] == "wire.msg":
                if e["dir"] == "req":
                    ex.req = e
                elif e["dir"] == "resp" and ex.resp is None and e.get("status", 0) >= 200:
                    ex.resp = e  # skip 1xx (e.g. 103 Early Hints, which Cloudflare sends) and trailers
            else:
                chunks = ex.chunks[e["dir"]]
                if e.get("replace"):
                    chunks.clear()
                chunks.append(e)

    def _match_wire(self) -> None:
        candidates: dict[tuple[str, str], list[Exchange]] = {}
        for ex in self.exchanges.values():
            if ex.req:
                candidates.setdefault((ex.req["method"], _strip_fragment(ex.req["url"])), []).append(ex)
        for hop in sorted(self.hops, key=lambda h: h.t):
            pool = [
                ex for ex in candidates.get((hop.method, _strip_fragment(hop.url)), [])
                if not ex.matched and ex.req and MATCH_WINDOW_MS[0] <= ex.req["t"] - hop.t <= MATCH_WINDOW_MS[1]
            ]  # fmt: skip
            if not pool:
                hop.match = "cache" if hop.from_cache else "ext-only"
                continue
            pool.sort(key=lambda ex: abs(ex.req["t"] - hop.t) if ex.req else 0)
            best = pool[0]
            best.matched = True
            hop.wire = best
            hop.match = "matched"
            if len(pool) > 1 and pool[1].req and best.req:
                if abs(abs(pool[1].req["t"] - hop.t) - abs(best.req["t"] - hop.t)) < AMBIGUOUS_MS:
                    hop.match = "ambiguous"

    def _build_steps(self) -> None:
        start_t = self.events[0]["t"] if self.events else 0.0
        self.steps = [Step(0, start_t, "start", "Browser opened")]
        for e in self.events:
            kind = e["type"]
            if kind == "action":
                self.steps.append(Step(len(self.steps), e["t"], "action", self._action_label(e), event=e))
            elif kind in ("nav.commit", "nav.history") and e.get("frameId") == 0:
                url = e.get("url", "")
                if url.startswith(("chrome://", "about:", "chrome-extension://", "data:", _OWN_PAGES)):
                    continue
                prev = self.steps[-1]
                redirect = {"client_redirect", "server_redirect"} & set(e.get("transitionQualifiers") or [])
                if prev.kind != "start" and e["t"] - prev.t <= MERGE_NAV_MS and (prev.kind == "action" or redirect):
                    prev.url = url
                    continue
                if kind == "nav.commit":
                    transition = e.get("transitionType") or "navigate"
                    label = f"{_NAV_LABELS.get(transition, transition)}: {_short(url)}"
                    step = Step(len(self.steps), self._nav_start(e, prev.t), "nav", label, url)
                else:
                    step = Step(len(self.steps), e["t"], "spa", f"route → {urlsplit(url).path}", url)
                self.steps.append(step)
        self.steps.sort(key=lambda s: s.t)
        for i, step in enumerate(self.steps):
            step.id = i
        for index, shot in enumerate(self.screenshots):
            self.steps[self.step_at(shot["t"])].screenshot = index

    def _nav_start(self, commit: Json, after: float) -> float:
        """A navigation step starts when its main-frame request started, not when the page committed."""
        chain = [
            h for h in self.hops
            if h.resource_type == "main_frame" and h.tab == commit.get("tabId")
            and after < h.t <= commit["t"] and commit["t"] - h.t <= NAV_LOOKBACK_MS
        ]  # fmt: skip
        final = next((h for h in reversed(chain) if _strip_fragment(h.url) == _strip_fragment(commit["url"])), None)
        if final is None:
            return float(commit["t"])
        return min(h.t for h in chain if h.request_id == final.request_id)

    @staticmethod
    def _action_label(e: Json) -> str:
        action = e.get("action")
        if action == "submit":
            method = str(e.get("formMethod") or "get").upper()
            return f"submit {method} {urlsplit(e.get('formAction') or '').path or '/'}"
        if action == "click":
            text = e.get("text") or ""
            return f'click "{text}"' if text else f"click {e.get('selector', '')}"
        return "press Enter"

    def step_at(self, t: float) -> int:
        starts = [s.t for s in self.steps]
        return max(0, bisect.bisect_right(starts, t) - 1)

    def _build_requests(self) -> None:
        for hop in self.hops:
            self.requests[hop.id] = Request(hop.id, hop.t, hop.url, hop.method, hop, hop.wire, self.step_at(hop.t))
        for ex in self.exchanges.values():
            if ex.matched or not ex.req:
                continue
            req = Request(ex.id, ex.req["t"], ex.req["url"], ex.req["method"], None, ex, self.step_at(ex.req["t"]))
            self.requests[ex.id] = req

    # --- state rows -----------------------------------------------------------

    def _cookie_row(self, c: Json) -> Row:
        rid = f"c|{c['domain']}|{c.get('path', '/')}|{c['name']}"
        row = self.rows.get(rid)
        if row is None:
            row = Row(rid, "cookie", c["domain"].lstrip("."), c["name"], c["domain"], c.get("path", "/"))
            self.rows[rid] = row
        row.badges.add("ext")
        row.attrs = {k: c.get(k) for k in ("secure", "httpOnly", "sameSite", "session", "hostOnly", "expirationDate")}
        return row

    def _build_cookie_rows(self) -> None:
        jar: dict[str, str] = {}
        seen_hello = False
        for e in self.events:
            if e["type"] == "hello":
                snapshot = {}
                for c in e.get("cookies") or []:
                    row = self._cookie_row(c)
                    snapshot[row.id] = c.get("value", "")
                # First hello = jar at capture start; later hellos (worker restarts) resync anything missed.
                baseline = not seen_hello
                for rid, value in snapshot.items():
                    if jar.get(rid) != value:
                        self.rows[rid].changes.append(Change(e["t"], rid, True, value, "resync", baseline=baseline))
                for rid in set(jar) - set(snapshot):
                    self.rows[rid].changes.append(Change(e["t"], rid, False, None, "resync", baseline=baseline))
                jar = snapshot
                seen_hello = True
            elif e["type"] == "cookie.change":
                c = e["cookie"]
                if e.get("removed") and e.get("cause") == "overwrite":
                    continue  # Chrome reports an update as remove(overwrite) + add
                row = self._cookie_row(c)
                if e.get("removed"):
                    jar.pop(row.id, None)
                    row.changes.append(Change(e["t"], row.id, False, None, e.get("cause", "")))
                else:
                    jar[row.id] = c.get("value", "")
                    row.changes.append(Change(e["t"], row.id, True, c.get("value", ""), e.get("cause", "")))

    def _build_storage_rows(self) -> None:
        previous: dict[str, dict[str, str]] = {}
        for e in self.events:
            if e["type"] != "storage":
                continue
            area, origin = e["area"], e["origin"]
            scope = origin if area == "local" else f"{origin}#tab{e.get('tabId')}"
            before = previous.get(f"{area}|{scope}", {})
            after = {str(k): str(v) for k, v in (e.get("items") or {}).items()}
            previous[f"{area}|{scope}"] = after
            for key in set(before) | set(after):
                if before.get(key) == after.get(key):
                    continue
                rid = f"{area}|{scope}|{key}"
                section = f"{'Local' if area == 'local' else 'Session'} Storage · {scope}"
                row = self.rows.setdefault(rid, Row(rid, area, section, key))
                row.badges.add("ext")
                present = key in after
                row.changes.append(Change(e["t"], rid, present, after.get(key), "javascript", source="javascript"))

    # --- lineage ----------------------------------------------------------------

    def _set_cookie_index(self) -> dict[str, list[tuple[float, Request, SetCookie]]]:
        """Every Set-Cookie header in the session, grouped by cookie name (parsed once)."""
        index: dict[str, list[tuple[float, Request, SetCookie]]] = {}
        for req in self.requests.values():
            t = req.resp_t
            if t is None:
                continue
            for raw in _header(req.resp_headers, "set-cookie"):
                parsed = parse_set_cookie(raw)
                index.setdefault(parsed.name, []).append((t, req, parsed))
        return index

    def _link_cookies(self) -> None:
        cookie_rows = [r for r in self.rows.values() if r.group == "cookie"]
        by_name: dict[str, list[Row]] = {}
        for row in cookie_rows:
            by_name.setdefault(row.name, []).append(row)
        set_cookies = self._set_cookie_index()

        for row in cookie_rows:
            responses = set_cookies.get(row.name, [])
            for change in row.changes:
                if change.baseline:
                    continue
                if change.cause in ("expired", "evicted"):
                    change.source = "browser"
                    continue
                window = [
                    (abs(change.t - t), req) for t, req, _ in responses
                    if -LINEAGE_AFTER_MS <= change.t - t <= LINEAGE_BEFORE_MS and domain_matches(row.domain, req.host)
                ]  # fmt: skip
                if window:
                    setter = min(window, key=lambda pair: pair[0])[1]
                    change.source = "header"
                    change.request = setter.id
                    if setter.wire:
                        row.badges.add("wire")
                else:
                    change.source = "javascript"

        for req in sorted(self.requests.values(), key=lambda r: r.t):
            parts = urlsplit(req.url)
            for name, _value in parse_cookie_header("; ".join(_header(req.req_headers, "cookie"))):
                for row in by_name.get(name, []):
                    if domain_matches(row.domain, parts.hostname or "") and path_matches(row.path, parts.path or "/"):
                        if req.id not in row.sent_by:
                            row.sent_by.append(req.id)
                        if row.id not in req.cookies_sent:
                            req.cookies_sent.append(row.id)
                        if req.wire:
                            row.badges.add("wire")
            self._set_cookie_outcomes(req, by_name)

        latest_disk = self.disk_cookies[-1]["cookies"] if self.disk_cookies else []
        on_disk = {(c["host"], c["name"], c.get("path", "/")) for c in latest_disk}
        for row in cookie_rows:
            if (row.domain, row.name, row.path) in on_disk:
                row.badges.add("disk")

    def _set_cookie_outcomes(self, req: Request, by_name: dict[str, list[Row]]) -> None:
        t = req.resp_t
        if t is None:
            return
        host = req.host
        initiator = req.hop.initiator if req.hop else None
        for raw in _header(req.resp_headers, "set-cookie"):
            sc = parse_set_cookie(raw)
            if not sc.name:
                continue
            rows = [r for r in by_name.get(sc.name, []) if domain_matches(r.domain, host)]
            change = next(
                (c for r in rows for c in r.changes
                 if not c.baseline and -LINEAGE_AFTER_MS <= c.t - t <= LINEAGE_BEFORE_MS),
                None,
            )  # fmt: skip
            outcome: Json = {"name": sc.name, "value": sc.value, "attrs": sc.attrs, "raw": raw,
                             "rowId": change.row if change else (rows[0].id if rows else None)}  # fmt: skip
            if change is not None:
                outcome["outcome"] = "stored" if change.present else "deleted"
            elif sc.deletes(t):
                outcome["outcome"] = "deleted"
            elif any(self._value_at(r, t) == sc.value for r in rows):
                outcome["outcome"] = "unchanged"
            else:
                outcome["outcome"] = "blocked"
                outcome["reason"] = blocked_reason(sc, req.url, initiator)
                self.blocked.append({"request": req.id, "step": req.step, "name": sc.name, "raw": raw,
                                     "reason": outcome["reason"]})  # fmt: skip
            req.cookies_set.append(outcome)

    @staticmethod
    def _value_at(row: Row, t: float) -> str | None:
        value = None
        for change in row.changes:
            if change.t > t:
                break
            value = change.value if change.present else None
        return value

    # --- serialisation ----------------------------------------------------------

    def _cells(self, row: Row) -> list[Json]:
        bounds = [s.t for s in self.steps[1:]] + [float("inf")]
        cells: list[Json] = []
        present, value = False, None
        for change in row.changes:
            if change.baseline:  # the jar as it was when capture started
                present, value = change.present, change.value
        changes = sorted((c for c in row.changes if not c.baseline), key=lambda c: c.t)
        index = 0
        for end in bounds:
            before_present, before_value = present, value
            touched = False
            while index < len(changes) and changes[index].t < end:
                present, value = changes[index].present, changes[index].value
                touched = True
                index += 1
            if not before_present and not present:
                state = "absent"
            elif not before_present:
                state = "added"
            elif not present:
                state = "removed"
            elif before_value != value:
                state = "changed"
            else:
                state = "same"
            cell: Json = {"state": state}
            if state in ("added", "changed"):
                cell["value"] = value
            if touched and state in ("same", "absent"):
                cell["touched"] = True
            cells.append(cell)
        return cells

    def _persistence(self, row: Row) -> Json:
        for snapshot in self.disk_cookies:
            if any((c["host"], c["name"], c.get("path", "/")) == (row.domain, row.name, row.path)
                   for c in snapshot["cookies"]):  # fmt: skip
                return {"onDisk": True, "since": snapshot["t"]}
        if row.attrs.get("session"):
            return {"onDisk": False, "note": "Session cookie: kept in memory only, gone when Chrome quits"}
        last_change = max((c.t for c in row.changes), default=0.0)
        if any(s["t"] > last_change + DISK_FLUSH_MS for s in self.disk_cookies):
            return {"onDisk": False, "note": "Persistent cookie not found on disk"}
        return {"onDisk": False, "note": "Not written yet (Chrome flushes cookies about every 30 s)"}

    def _row_json(self, row: Row) -> Json:
        initial = None
        for change in row.changes:
            if change.baseline:
                initial = change.value if change.present else None
        data: Json = {
            "id": row.id, "group": row.group, "section": row.section, "name": row.name,
            "cells": self._cells(row), "initial": initial, "badges": sorted(row.badges),
        }  # fmt: skip
        if row.group == "cookie":
            data["domain"], data["path"], data["attrs"] = row.domain, row.path, row.attrs
            data["setBy"] = [
                {"t": c.t, "step": self.step_at(c.t), "source": c.source, "request": c.request}
                for c in row.changes if c.present and not c.baseline
            ]  # fmt: skip
            data["removedBy"] = [
                {"t": c.t, "step": self.step_at(c.t), "source": c.source, "request": c.request, "cause": c.cause}
                for c in row.changes if not c.present and not c.baseline
            ]  # fmt: skip
            data["sentBy"] = row.sent_by
            data["persistence"] = self._persistence(row)
        return data

    def _request_json(self, req: Request) -> Json:
        hop, wire = req.hop, req.wire
        status = hop.status if hop and hop.status is not None else (wire.resp["status"] if wire and wire.resp else None)
        match = hop.match if hop else "wire-only"
        return {
            "id": req.id, "step": req.step, "t": req.t, "method": req.method, "url": req.url, "status": status,
            "resourceType": hop.resource_type if hop else None, "initiator": hop.initiator if hop else None,
            "tabId": hop.tab if hop else None, "frameId": hop.frame if hop else None, "match": match,
            "proto": wire.req["proto"] if wire and wire.req else None,
            "redirectTo": hop.redirect_to if hop else None, "fromCache": hop.from_cache if hop else False,
            "error": hop.error if hop else None,
            "browserInternal": match == "wire-only" and req.host.endswith(_BROWSER_HOSTS),
            "cookiesSent": req.cookies_sent,
            "cookiesSet": [c["rowId"] for c in req.cookies_set if c.get("rowId") and c["outcome"] == "stored"],
            "blocked": sum(1 for c in req.cookies_set if c["outcome"] == "blocked"),
        }  # fmt: skip

    def _disk_json(self) -> list[Json]:
        per_kind: dict[str, list[list[Any]]] = {}
        for e in self.events:
            if e["type"] != "disk.change":
                continue
            cells = per_kind.setdefault(e["kind"], [[] for _ in self.steps])
            cells[self.step_at(e["t"])].extend(e.get("items") or [])
        return [
            {"kind": kind, "label": _DISK_LABELS.get(kind, kind),
             "cells": [{"count": len(items), "items": items} for items in cells]}
            for kind, cells in per_kind.items()
        ]  # fmt: skip

    def _status(self) -> Json:
        ext = [e for e in self.events if not e["type"].startswith(("wire.", "disk.", "capture."))]
        latest: Json = {}
        for e in self.events:
            if e["type"] == "capture.status":
                latest[e["component"]] = {"ok": e["ok"], "detail": e.get("detail", ""), "t": e["t"]}
        return {
            "extensionEvents": len(ext), "lastExtensionEvent": ext[-1]["t"] if ext else None,
            "wireMessages": sum(1 for e in self.events if e["type"] == "wire.msg"),
            "diskSnapshots": len(self.disk_cookies), "components": latest,
        }  # fmt: skip

    def model(self) -> Json:
        rows = sorted(self.rows.values(), key=lambda r: (r.group != "cookie", r.section, r.name))
        return {
            "steps": [{k: v for k, v in vars(s).items() if k != "event"} for s in self.steps],
            "rows": [self._row_json(r) for r in rows],
            "requests": [self._request_json(r) for r in sorted(self.requests.values(), key=lambda r: r.t)],
            "blocked": self.blocked,
            "disk": self._disk_json(),
            "status": self._status(),
        }

    # --- request detail -----------------------------------------------------------

    def _wire_body(self, ex: Exchange, direction: str, content_type: str, secrets: set[str] | None) -> Json:
        msg = ex.req if direction == "req" else ex.resp
        headers = msg["headers"] if msg else []
        if msg and msg.get("body"):
            data = base64.b64decode(msg["body"]["b64"])
            decoded = bool(msg["body"].get("decoded"))
        else:
            chunks = ex.chunks[direction]
            if any(c.get("skipped") for c in chunks):
                return {"kind": "skipped", "size": sum(c.get("len", 0) for c in chunks), "contentType": content_type}
            data = b"".join(base64.b64decode(c["b64"]) for c in chunks if "b64" in c)
            decoded = False
        error = None
        encoding = ", ".join(_header(headers, "content-encoding"))
        if encoding and not decoded:
            data, error = decompress(data, encoding)
        result = describe(data, content_type, secrets)
        if error:
            result["decodeError"] = error
        return result

    def _request_body(self, req: Request, secrets: set[str] | None) -> Json:
        content_type = ", ".join(_header(req.req_headers, "content-type"))
        if req.wire and (req.wire.req and req.wire.req.get("body") or req.wire.chunks["req"]):
            return self._wire_body(req.wire, "req", content_type, secrets)
        body = req.hop.body if req.hop else None
        if not body:
            return {"kind": "none", "size": 0}
        if body.get("formData"):
            return describe_form_data(body["formData"], secrets)
        if body.get("raw"):
            data = b"".join(base64.b64decode(p["base64"]) for p in body["raw"] if "base64" in p)
            return describe(data, content_type, secrets)
        return {"kind": "unavailable", "reason": body.get("error", "unknown")}

    def captured(self, request_id: str) -> Captured:
        """The request exactly as sent (wire bytes when available), for replay."""
        req = self.requests[request_id]
        body = b""
        if req.wire and req.wire.req and req.wire.req.get("body"):
            body = base64.b64decode(req.wire.req["body"]["b64"])
        elif req.wire and req.wire.chunks["req"]:
            body = b"".join(base64.b64decode(c["b64"]) for c in req.wire.chunks["req"] if "b64" in c)
        elif req.hop and req.hop.body:
            if req.hop.body.get("formData"):
                body = urlencode([(k, v) for k, vs in req.hop.body["formData"].items() for v in vs]).encode()
            elif req.hop.body.get("raw"):
                body = b"".join(base64.b64decode(p["base64"]) for p in req.hop.body["raw"] if "base64" in p)
        return Captured(req.method, req.url, req.req_headers, body)

    def detail(self, request_id: str, reveal: bool = False) -> Json:
        req = self.requests[request_id]
        secrets = None if reveal else self.secret_fields
        content_type = ", ".join(_header(req.resp_headers, "content-type"))
        if req.wire and req.wire.resp:
            response_body = self._wire_body(req.wire, "resp", content_type, secrets)
        else:
            reason = "served from cache" if req.hop and req.hop.from_cache else "not seen on the wire"
            response_body = {"kind": "unavailable", "reason": reason}
        sent_values = parse_cookie_header("; ".join(_header(req.req_headers, "cookie")))
        return {
            **self._request_json(req),
            "query": [list(p) for p in parse_qsl(urlsplit(req.url).query, keep_blank_values=True)],
            "requestHeaders": {"wire": req.wire.req["headers"] if req.wire and req.wire.req else None,
                               "ext": req.hop.req_headers if req.hop else None},
            "responseHeaders": {"wire": req.wire.resp["headers"] if req.wire and req.wire.resp else None,
                                "ext": req.hop.resp_headers if req.hop else None},
            "requestBody": self._request_body(req, secrets),
            "responseBody": response_body,
            "cookiesSentValues": [{"name": n, "value": v} for n, v in sent_values],
            "cookiesSet": req.cookies_set,  # full outcomes here; the summary only lists stored row ids
            "timing": {"start": req.t, "response": req.resp_t,
                       "wireRequest": req.wire.req["t"] if req.wire and req.wire.req else None},
        }  # fmt: skip
