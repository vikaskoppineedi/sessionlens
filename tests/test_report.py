import json
import re
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any

from sessionlens.event_store import EventStore
from sessionlens.export import BODY_INLINE_LIMIT, build_export, export_zip, write_export
from sessionlens.model import Analysis
from sessionlens.report import build_report
from tests.test_model import b64, session_events

INDEX = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/png" href="/favicon.png" />
    <title>SessionLens</title>
    <script type="module" crossorigin src="/assets/index-abc.js"></script>
    <link rel="stylesheet" crossorigin href="/assets/index-def.css">
  </head>
  <body>
    <div id="root"></div>
  </body>
</html>
"""
JS = 'const tag = "</script>"; console.log(tag);'
CSS = "body { color: red; }"


def fake_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text(INDEX)
    (dist / "assets" / "index-abc.js").write_text(JS)
    (dist / "assets" / "index-def.css").write_text(CSS)
    return dist


def embedded(html: str) -> dict[str, Any]:
    match = re.search(r'<script id="sessionlens-data" type="application/json">(.*?)</script>', html, re.S)
    assert match
    data: dict[str, Any] = json.loads(match.group(1))
    return data


def report(events: list[dict[str, Any]] | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    _, files, data = build_export(Analysis(events if events is not None else session_events()), "s1")
    return data, files


def test_report_data_shape() -> None:
    data, files = report()
    assert data["session"] == "s1"
    assert data["model"]["live"] is False
    assert len(data["model"]["steps"]) == 4
    request_ids = {r["id"] for r in data["model"]["requests"] if r["match"] != "wire-only"}
    assert set(data["details"]) == request_ids
    assert data["screenshots"]
    for path in data["screenshots"].values():
        assert path in files
    assert all(isinstance(k, str) for k in data["screenshots"])


def test_report_inlines_assets(tmp_path: Path) -> None:
    data, _ = report()
    html = build_report(data, fake_dist(tmp_path))
    assert html is not None
    assert "/assets/" not in html
    assert "favicon" not in html
    assert f"<style>{CSS}</style>" in html
    assert '<script type="module">const tag = "<\\/script>"' in html
    assert "<title>SessionLens · s1</title>" in html
    assert html.index('id="sessionlens-data"') < html.index('<script type="module">')
    parsed = embedded(html)
    assert parsed["model"]["steps"] and parsed["model"]["live"] is False
    assert parsed == json.loads(json.dumps(data))


def test_json_blob_cannot_close_its_script(tmp_path: Path) -> None:
    html = build_report({"session": "s1", "model": {"x": "</script><b>"}}, fake_dist(tmp_path))
    assert html is not None
    assert "</script><b>" not in html
    assert embedded(html)["model"]["x"] == "</script><b>"


def test_no_report_without_built_ui(tmp_path: Path) -> None:
    assert build_report({"session": "s1"}, tmp_path / "missing") is None


def test_large_bodies_are_unavailable_in_details() -> None:
    events = session_events()
    big = b"<html>" + b"x" * BODY_INLINE_LIMIT + b"</html>"
    for e in events:
        if e["type"] == "wire.msg" and e.get("dir") == "resp" and e["conn"] == "tcp:1":
            e["headers"] = [["content-type", "text/html"]]
        if e["type"] == "wire.data" and e["conn"] == "tcp:1":
            e["b64"] = b64(big)
    data, _ = report(events)
    body = next(d["responseBody"] for d in data["details"].values() if d["url"] == "https://www.example.com/")
    assert body["kind"] == "unavailable"
    assert "bodies/r0001-response.html" in body["reason"]
    assert str(len(big)) in body["reason"]


def test_script_bodies_are_unavailable_in_details() -> None:
    events = session_events()
    for e in events:
        if e["type"] == "req.start" and e["requestId"] == "1":
            e["resourceType"] = "script"
    data, _ = report(events)
    body = next(d["responseBody"] for d in data["details"].values() if d["url"] == "https://www.example.com/")
    assert body == {"kind": "unavailable", "reason": "script/stylesheet body not included"}


def test_small_bodies_stay_inline_in_details() -> None:
    data, _ = report()
    body = next(d["responseBody"] for d in data["details"].values() if d["url"] == "https://www.example.com/")
    assert body["json"] == {"hello": "world"}


def write_session(tmp_path: Path) -> Path:
    session = tmp_path / "20260101-120000"
    session.mkdir()
    store = EventStore(session / "events.jsonl")
    for e in session_events():
        store.append(e)
    return session


def test_write_export_writes_report(tmp_path: Path) -> None:
    out = write_export(write_session(tmp_path), dist_dir=fake_dist(tmp_path))
    html = (out / "index.html").read_text()
    data = embedded(html)
    assert data["session"] == "20260101-120000"
    for path in data["screenshots"].values():
        assert (out / path).exists()


def test_write_export_without_ui_has_no_report(tmp_path: Path) -> None:
    out = write_export(write_session(tmp_path), dist_dir=tmp_path / "missing")
    assert (out / "session.json").exists()
    assert not (out / "index.html").exists()


def test_zip_includes_report(tmp_path: Path) -> None:
    data = export_zip(Analysis(session_events()), "s1", fake_dist(tmp_path))
    assert "index.html" in zipfile.ZipFile(BytesIO(data)).namelist()
