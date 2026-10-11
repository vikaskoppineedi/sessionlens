"""Session export: one timeline JSON plus screenshots and large bodies, for reading by other tools.

Covers only what happened in the capture browser (requests the extension saw), in the same shape as
the analyzer: steps → requests, cookie diffs, storage diffs, disk writes. Password fields are masked.
"""

import base64
import io
import json
import shutil
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sessionlens.event_store import EventStore
from sessionlens.model import Analysis

Json = dict[str, Any]
FORMAT = "sessionlens-export/1"
BODY_INLINE_LIMIT = 64 * 1024
SKIP_RESPONSE_TYPES = {"script", "stylesheet"}  # site code: large, rarely what you analyse
_ACTION_FIELDS = ("selector", "tag", "text", "href", "formAction", "formMethod", "fields", "x", "y")
_COOKIE_ATTRS = ("httpOnly", "secure", "sameSite", "session", "hostOnly", "expirationDate")
_EXT_BY_TYPE = {"html": "html", "json": "json", "xml": "xml", "javascript": "js", "css": "css"}

README = """# sessionlens export

`session.json` is the timeline (format sessionlens-export/1). Times: `atMs` = ms since session start.

- `steps[]` — step 0 = browser opened; then one entry per action (click/submit/Enter) or navigation.
  Each has `pageUrl`, `screenshot` (path in screenshots/), and:
  - `requests[]` — what the browser sent and got back. `id` (r0001…) is referenced elsewhere.
    Bodies: `kind` form/json/text/binary/none/skipped/unavailable; bodies over 64 KB are in bodies/.
    `cookiesSent` = cookie keys ("<domain> <name>"); `cookiesSet` = what each Set-Cookie did.
  - `cookieChanges[]` / `storageChanges[]` — `before` → `after`, with what caused it.
  - `disk[]` — files Chrome wrote to its profile during the step.
- `finalState` — cookies and storage at the end.

Password fields are masked. Cookie values and tokens are real: keep this folder private.
"""


def _iso(t: float) -> str:
    return datetime.fromtimestamp(t / 1000, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _value_at(row: Json, step: int) -> str | None:
    value = row.get("initial")
    for cell in row["cells"][: step + 1]:
        if cell["state"] in ("added", "changed"):
            value = cell.get("value")
        elif cell["state"] == "removed":
            value = None
    return value


def cookie_key(row: Json) -> str:
    path = row.get("path") or "/"
    return f"{row['domain']} {row['name']}" + ("" if path == "/" else f" {path}")


def build_export(analysis: Analysis, session_id: str) -> tuple[Json, dict[str, bytes]]:
    """Returns (session.json content, {relative path: bytes} for screenshots and bodies)."""
    model = analysis.model()
    files: dict[str, bytes] = {}
    start = model["steps"][0]["t"]
    requests = [r for r in model["requests"] if r["match"] != "wire-only"]
    rid = {r["id"]: f"r{i:04d}" for i, r in enumerate(requests, 1)}
    rows = {r["id"]: r for r in model["rows"]}

    def body(data: Json, name: str, skip: bool) -> Json:
        kind = data.get("kind")
        meta: Json = {k: data[k] for k in ("kind", "size", "contentType") if k in data}
        if skip and kind in ("text", "json"):
            return {**meta, "kind": "skipped", "reason": "script/stylesheet body not exported"}
        if kind == "binary":
            return meta
        if kind in ("text", "json"):
            text = data["text"] if kind == "text" else json.dumps(data["json"], ensure_ascii=False, indent=2)
            raw = text.encode()
            if len(raw) <= BODY_INLINE_LIMIT:
                return data
            ctype = str(data.get("contentType", "")).lower()
            path = f"bodies/{name}.{next((e for k, e in _EXT_BY_TYPE.items() if k in ctype), 'txt')}"
            files[path] = raw
            return {**meta, "file": path, **({"truncated": True} if data.get("truncated") else {})}
        return data

    def request(summary: Json) -> Json:
        d = analysis.detail(summary["id"])  # masked: password fields replaced
        short = rid[summary["id"]]
        host = urlsplit(d["url"]).hostname or ""
        return {
            "id": short, "atMs": round(d["t"] - start), "method": d["method"], "url": d["url"],
            "type": d["resourceType"], "status": d["status"], "redirectTo": d["redirectTo"],
            "protocol": d["proto"], "initiator": d["initiator"], "fromCache": d["fromCache"], "error": d["error"],
            "query": d["query"],
            "requestHeaders": d["requestHeaders"]["wire"] or d["requestHeaders"]["ext"] or [],
            "requestBody": body(d["requestBody"], f"{short}-request", False),
            "responseHeaders": d["responseHeaders"]["wire"] or d["responseHeaders"]["ext"] or [],
            "responseBody": body(d["responseBody"], f"{short}-response", d["resourceType"] in SKIP_RESPONSE_TYPES),
            "cookiesSent": [cookie_key(rows[i]) for i in d["cookiesSent"] if i in rows],
            "cookiesSet": [
                {"cookie": cookie_key(rows[c["rowId"]]) if c.get("rowId") in rows else f"{host} {c['name']}",
                 "outcome": c["outcome"], **({"reason": c["reason"]} if c.get("reason") else {})}
                for c in d["cookiesSet"]
            ],
        }  # fmt: skip

    def cause(lineage: list[Json], step: int) -> Json | None:
        hits = [x for x in lineage if x["step"] == step]
        return {"source": hits[-1]["source"], "request": rid.get(hits[-1]["request"] or "")} if hits else None

    steps_out = []
    for step in model["steps"]:
        i = step["id"]
        cookie_changes, storage_changes = [], []
        for row in model["rows"]:
            state = row["cells"][i]["state"]
            if state not in ("added", "changed", "removed"):
                continue
            before = _value_at(row, i - 1) if i else row.get("initial")
            change = {"change": state, "before": before, "after": _value_at(row, i)}
            if row["group"] == "cookie":
                lineage = row["removedBy"] if state == "removed" else row["setBy"]
                cookie_changes.append({
                    "cookie": cookie_key(row), **change,
                    "attributes": {k: row["attrs"].get(k) for k in _COOKIE_ATTRS},
                    ("removedBy" if state == "removed" else "setBy"): cause(lineage, i),
                })  # fmt: skip
            else:
                area, scope, key = row["id"].split("|", 2)
                storage_changes.append({"area": f"{area}Storage", "origin": scope, "key": key, **change})
        shot = None
        if step["screenshot"] is not None:
            shot = f"screenshots/step-{i:02d}.jpg"
            files[shot] = base64.b64decode(analysis.screenshots[step["screenshot"]]["dataUrl"].partition(",")[2])
        event = analysis.steps[i].event or {}
        action = None
        if event:
            action = {"type": event.get("action"), "label": step["label"],
                      **{k: event[k] for k in _ACTION_FIELDS if event.get(k) is not None}}  # fmt: skip
        steps_out.append({
            "step": i, "kind": step["kind"], "label": step["label"], "atMs": round(step["t"] - start),
            "time": _iso(step["t"]), "action": action, "pageUrl": step["url"], "screenshot": shot,
            "requests": [request(r) for r in requests if r["step"] == i],
            "cookieChanges": cookie_changes, "storageChanges": storage_changes,
            "disk": [{"kind": d["kind"], "label": d["label"], "items": d["cells"][i]["items"]}
                     for d in model["disk"] if d["cells"][i]["count"]],
        })  # fmt: skip

    last = len(model["steps"]) - 1
    final: Json = {"cookies": [], "localStorage": {}, "sessionStorage": {}}
    for row in model["rows"]:
        value = _value_at(row, last)
        if value is None:
            continue
        if row["group"] == "cookie":
            final["cookies"].append({"domain": row["domain"], "name": row["name"], "path": row["path"], "value": value,
                                     "attributes": {k: row["attrs"].get(k) for k in _COOKIE_ATTRS}})  # fmt: skip
        else:
            area, scope, key = row["id"].split("|", 2)
            final[f"{area}Storage"].setdefault(scope, {})[key] = value

    user_agent = next((v for r in sorted(analysis.requests.values(), key=lambda r: r.t)
                       for n, v in r.req_headers if n.lower() == "user-agent"), None)  # fmt: skip
    end = max((e.get("t", 0) for e in analysis.events), default=start)
    doc = {
        "format": FORMAT,
        "session": {"id": session_id, "startedAt": _iso(start), "durationMs": round(end - start),
                    "userAgent": user_agent},
        "steps": steps_out,
        "finalState": final,
    }  # fmt: skip
    return doc, files


def _contents(analysis: Analysis, session_id: str) -> dict[str, bytes]:
    doc, files = build_export(analysis, session_id)
    return {"session.json": json.dumps(doc, ensure_ascii=False, indent=2).encode(), "README.md": README.encode(),
            **files}  # fmt: skip


def write_export(session_dir: Path) -> Path:
    """(Re)write sessions/<id>/export/ from the session's events.jsonl."""
    analysis = Analysis(EventStore.load(session_dir / "events.jsonl").events)
    out = session_dir / "export"
    shutil.rmtree(out, ignore_errors=True)
    for name, data in _contents(analysis, session_dir.name).items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return out


def export_zip(analysis: Analysis, session_id: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in _contents(analysis, session_id).items():
            archive.writestr(name, data)
    return buffer.getvalue()
