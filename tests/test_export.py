import base64
import json
import zipfile
from pathlib import Path
from typing import Any

from sessionlens.event_store import EventStore
from sessionlens.export import BODY_INLINE_LIMIT, build_export, write_export
from sessionlens.model import Analysis, prune_unmatched_wire
from tests.test_model import T0, b64, session_events


def export(events: list[dict[str, Any]] | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    doc, files, _ = build_export(Analysis(events if events is not None else session_events()), "s1")
    return doc, files


def all_requests(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return [r for step in doc["steps"] for r in step["requests"]]


def test_only_browser_requests_are_exported() -> None:
    doc, _ = export()
    urls = [r["url"] for r in all_requests(doc)]
    assert "https://update.googleapis.com/check" not in urls  # Chrome background, wire only
    assert urls == ["https://www.example.com/", "https://www.example.com/login", "https://www.example.com/home"]


def test_steps_carry_action_page_and_screenshot() -> None:
    doc, files = export()
    steps = doc["steps"]
    assert [s["step"] for s in steps] == [0, 1, 2, 3]
    assert steps[1]["screenshot"] == "screenshots/step-01.jpg"
    assert files["screenshots/step-01.jpg"] == base64.b64decode("AA==")
    assert steps[2]["action"]["type"] == "submit"
    assert steps[2]["action"]["fields"][0] == {"name": "user", "type": "text", "value": "demo"}
    assert steps[2]["pageUrl"] == "https://www.example.com/home"
    assert steps[3]["action"]["label"] == 'click "Log out"'
    assert steps[0]["atMs"] == 0 and steps[2]["atMs"] == 5000


def test_request_ids_are_short_and_cross_referenced() -> None:
    doc, _ = export()
    ids = [r["id"] for r in all_requests(doc)]
    assert ids == ["r0001", "r0002", "r0003"]
    sid_change = next(c for c in doc["steps"][2]["cookieChanges"] if c["cookie"] == "www.example.com sid")
    assert sid_change["setBy"] == {"source": "header", "request": "r0002"}


def test_cookie_changes_show_before_and_after() -> None:
    doc, _ = export()
    changes = {c["cookie"]: c for c in doc["steps"][2]["cookieChanges"]}
    assert changes["www.example.com sid"]["change"] == "changed"
    assert changes["www.example.com sid"]["before"] == "anon"
    assert changes["www.example.com sid"]["after"] == "user42"
    assert changes["www.example.com sid"]["attributes"]["httpOnly"] is True
    assert changes["www.example.com old"] == {**changes["www.example.com old"], "change": "removed", "before": "1",
                                              "after": None}
    assert changes["www.example.com theme"]["setBy"] == {"source": "javascript", "request": None}


def test_storage_changes() -> None:
    doc, _ = export()
    [change] = doc["steps"][2]["storageChanges"]
    assert change == {"area": "localStorage", "origin": "https://www.example.com", "key": "token", "change": "added",
                      "before": None, "after": "eyJ"}


def test_request_detail_is_complete_with_passwords_masked() -> None:
    doc, _ = export()
    login = all_requests(doc)[1]
    assert login["method"] == "POST" and login["status"] == 303
    assert login["redirectTo"] == "https://www.example.com/home"
    assert login["requestBody"]["form"] == [["user", "demo"], ["pw", "••••••"]]
    assert "hunter2" not in json.dumps(doc)
    assert login["cookiesSent"] == ["www.example.com old", "www.example.com sid"]
    outcomes = {c["cookie"]: c for c in login["cookiesSet"]}
    assert outcomes["www.example.com track"]["outcome"] == "blocked"
    assert "requires Secure" in outcomes["www.example.com track"]["reason"]
    first = all_requests(doc)[0]
    assert first["responseBody"] == {"kind": "json", "size": 18, "contentType": "application/json",
                                     "json": {"hello": "world"}}
    assert first["requestHeaders"] == [["cookie", "old=1"], ["user-agent", "UA"]]
    assert first["protocol"] == "h2"


def test_large_bodies_go_to_files() -> None:
    events = session_events()
    big = b"<html>" + b"x" * BODY_INLINE_LIMIT + b"</html>"
    for e in events:
        if e["type"] == "wire.msg" and e.get("dir") == "resp" and e["conn"] == "tcp:1":
            e["headers"] = [["content-type", "text/html"]]
        if e["type"] == "wire.data" and e["conn"] == "tcp:1":
            e["b64"] = b64(big)
    doc, files = export(events)
    body = all_requests(doc)[0]["responseBody"]
    assert body["file"] == "bodies/r0001-response.html"
    assert "text" not in body
    assert files["bodies/r0001-response.html"] == big


def test_script_bodies_are_skipped() -> None:
    events = session_events()
    for e in events:
        if e["type"] == "req.start" and e["requestId"] == "1":
            e["resourceType"] = "script"
    body = all_requests(export(events)[0])[0]["responseBody"]
    assert body["kind"] == "skipped"


def test_final_state_and_session_info() -> None:
    doc, _ = export()
    assert doc["format"] == "sessionlens-export/1"
    assert doc["session"]["id"] == "s1"
    assert doc["session"]["userAgent"] == "UA"
    final = {f"{c['domain']} {c['name']}": c["value"] for c in doc["finalState"]["cookies"]}
    assert final == {"www.example.com sid": "user42"}
    assert doc["finalState"]["localStorage"] == {"https://www.example.com": {"first_visit": "2"}}


def test_empty_session_exports() -> None:
    doc, files = export([])
    assert len(doc["steps"]) == 1 and doc["steps"][0]["requests"] == []
    assert files == {}


def test_prune_keeps_only_browser_wire_data() -> None:
    pruned = prune_unmatched_wire(session_events())
    wire_urls = {e.get("url") for e in pruned if e["type"] == "wire.msg" and e.get("dir") == "req"}
    assert wire_urls == {"https://www.example.com/"}
    assert sum(1 for e in pruned if e["type"] == "wire.data") == 1
    assert sum(1 for e in pruned if e["type"] == "cookie.change") == 6  # extension events untouched
    assert [e["t"] for e in pruned] == sorted(e["t"] for e in pruned)


def test_write_export_creates_folder(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.jsonl")
    for e in session_events():
        store.append(e)
    out = write_export(tmp_path)
    assert out == tmp_path / "export"
    doc = json.loads((out / "session.json").read_text())
    assert doc["session"]["id"] == tmp_path.name
    assert (out / "screenshots" / "step-01.jpg").exists()
    assert "session.json" in (out / "README.md").read_text()
    (out / "stale.txt").write_text("old")
    write_export(tmp_path)
    assert not (out / "stale.txt").exists()


def test_zip_round_trip(tmp_path: Path) -> None:
    from sessionlens.export import export_zip

    data = export_zip(Analysis(session_events()), "s1")
    path = tmp_path / "x.zip"
    path.write_bytes(data)
    names = zipfile.ZipFile(path).namelist()
    assert {"session.json", "README.md", "screenshots/step-01.jpg"} <= set(names)


def test_capture_start_page_is_not_a_step() -> None:
    events = [{"type": "nav.commit", "t": T0, "tabId": 1, "frameId": 0, "url": "http://127.0.0.1:8765/claim?nonce=x",
               "transitionType": "auto_toplevel", "transitionQualifiers": []}]
    assert len(Analysis(events).model()["steps"]) == 1


def test_security_answers_and_one_time_codes_are_masked() -> None:
    from sessionlens.bodies import describe

    body = b"kba1_response=blue&otp=123456&security_answer=rex&username=demo"
    form = dict(describe(body, "application/x-www-form-urlencoded", set())["form"])
    assert form == {"kba1_response": "••••••", "otp": "••••••", "security_answer": "••••••", "username": "demo"}
