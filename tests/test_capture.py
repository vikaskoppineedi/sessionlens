import json
import os
import stat
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sessionlens.chrome import build_chrome_command
from sessionlens.event_store import EventStore
from sessionlens.ingest import create_ingest_app
from sessionlens.session import create_session_dir, profile_in_use, restore_pristine, save_pristine

ORIGIN = "chrome-extension://testextensionid"


def test_session_dir_is_private_and_unique(tmp_path: Path) -> None:
    now = datetime(2026, 10, 10, 12, 0, 0)
    first = create_session_dir(tmp_path, now)
    second = create_session_dir(tmp_path, now)
    assert first != second
    assert stat.S_IMODE(first.stat().st_mode) == 0o700


def test_save_then_restore_pristine_resets_browsing_data(tmp_path: Path) -> None:
    live, pristine = tmp_path / "capture", tmp_path / "capture.pristine"
    (live / "Default" / "Cache").mkdir(parents=True)
    (live / "Default" / "Preferences").write_text('{"extension": true}')
    (live / "Default" / "Cache" / "x").write_text("cached")
    (live / "SingletonSocket").write_text("")
    save_pristine(live, pristine)
    assert not (pristine / "Default" / "Cache").exists()
    assert not (pristine / "SingletonSocket").exists()

    (live / "Default" / "Cookies").write_text("browsed")
    restore_pristine(pristine, live)
    assert (live / "Default" / "Preferences").read_text() == '{"extension": true}'
    assert not (live / "Default" / "Cookies").exists()


def test_pristine_never_keeps_browsing_data(tmp_path: Path) -> None:
    live, pristine = tmp_path / "capture", tmp_path / "capture.pristine"
    (live / "Default" / "Local Storage").mkdir(parents=True)
    (live / "Default" / "Cookies").write_text("NID from setup")
    (live / "Default" / "History").write_text("chrome://extensions")
    (live / "Default" / "Secure Preferences").write_text("{}")
    save_pristine(live, pristine)
    assert sorted(p.name for p in (pristine / "Default").iterdir()) == ["Secure Preferences"]

    # A pristine copy made by an older version still restores clean.
    (pristine / "Default" / "Cookies").write_text("stale")
    restore_pristine(pristine, live)
    assert sorted(p.name for p in (live / "Default").iterdir()) == ["Secure Preferences"]


def test_restore_requires_pristine(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        restore_pristine(tmp_path / "missing", tmp_path / "live")


def test_restore_refuses_while_chrome_runs(tmp_path: Path) -> None:
    live, pristine = tmp_path / "capture", tmp_path / "capture.pristine"
    pristine.mkdir()
    live.mkdir()
    (live / "SingletonLock").symlink_to(f"host-{os.getpid()}")
    assert profile_in_use(live)
    with pytest.raises(RuntimeError, match="still running"):
        restore_pristine(pristine, live)


def test_stale_lock_is_not_in_use(tmp_path: Path) -> None:
    (tmp_path / "SingletonLock").symlink_to("host-999999")
    assert not profile_in_use(tmp_path)


def test_chrome_command_sets_keylog_without_debug_flags(tmp_path: Path) -> None:
    argv, env = build_chrome_command("/chrome", tmp_path / "profile", tmp_path / "keys.log", ["https://x.com"])
    assert argv[0] == "/chrome"
    assert f"--user-data-dir={tmp_path / 'profile'}" in argv
    assert argv[-1] == "https://x.com"
    assert env["SSLKEYLOGFILE"] == str(tmp_path / "keys.log")
    assert not any("debug" in a or "load-extension" in a or "automation" in a for a in argv)


def test_event_store_appends_json_lines(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.jsonl")
    store.append({"type": "cookie.change", "name": "ключ"})
    store.append({"type": "req.start"})
    lines = (tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    assert first["name"] == "ключ"
    assert isinstance(first["recv"], float)
    assert json.loads(lines[1])["type"] == "req.start"


NONCE = "session-nonce"


def make_client(tmp_path: Path) -> tuple[TestClient, Path]:
    path = tmp_path / "events.jsonl"
    return TestClient(create_ingest_app(EventStore(path), ORIGIN, NONCE)), path


def stored_types(path: Path) -> list[str]:
    return [json.loads(line)["type"] for line in path.read_text().splitlines()] if path.exists() else []


def test_ingest_stores_events_after_claim_and_drops_pings(tmp_path: Path) -> None:
    client, path = make_client(tmp_path)
    with client.websocket_connect("/ingest", headers={"origin": ORIGIN}) as ws:
        ws.send_text('{"type":"ping"}')
        ws.send_text("not json")
        ws.send_text('{"type":"hello","cookies":[]}')
        ws.send_text(json.dumps({"type": "claim", "nonce": NONCE}))
        ws.send_text('{"type":"cookie.change"}')
    assert stored_types(path) == ["hello", "cookie.change"]


def test_ingest_ignores_browsers_that_never_claim(tmp_path: Path) -> None:
    """The same extension installed in your everyday Chrome must not leak into the capture."""
    client, path = make_client(tmp_path)
    with client.websocket_connect("/ingest", headers={"origin": ORIGIN}) as ws:
        ws.send_text('{"type":"hello","cookies":[{"name":"personal"}]}')
        ws.send_text('{"type":"req.start"}')
    assert stored_types(path) == []


def test_ingest_closes_on_wrong_nonce(tmp_path: Path) -> None:
    client, path = make_client(tmp_path)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ingest", headers={"origin": ORIGIN}) as ws:
            ws.send_text('{"type":"hello"}')
            ws.send_text('{"type":"claim","nonce":"old-session"}')
            ws.receive_text()
    assert stored_types(path) == []


def test_claim_page_is_served(tmp_path: Path) -> None:
    client, _ = make_client(tmp_path)
    page = client.get(f"/claim?nonce={NONCE}")
    assert page.status_code == 200
    assert "capture window" in page.text


def test_ingest_rejects_other_origins(tmp_path: Path) -> None:
    client, path = make_client(tmp_path)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ingest", headers={"origin": "https://evil.example"}) as ws:
            ws.send_text('{"type":"hello"}')
            ws.receive_text()
    assert not path.exists()
