import json
from pathlib import Path
from typing import Any

import httpx2
from fastapi.testclient import TestClient

from sessionlens.compare import compare
from sessionlens.event_store import EventStore
from sessionlens.replay import Captured, Replayer, Result, similar
from sessionlens.web import Registry, create_web_app
from tests.test_model import session_events


def write_session(root: Path, session_id: str, events: list[dict[str, Any]]) -> None:
    (root / session_id).mkdir(parents=True)
    with (root / session_id / "events.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


class FakeServer:
    """Pretends the site needs only the 'sid' cookie and an Authorization header."""

    def __init__(self) -> None:
        self.calls: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        ok = "sid=" in request.headers.get("cookie", "") and "authorization" in request.headers
        return httpx2.Response(200 if ok else 401, text="orders" * 20 if ok else "no")


def client(tmp_path: Path, replayer: Replayer | None = None) -> TestClient:
    write_session(tmp_path, "20261010-120000", session_events())
    registry = Registry(tmp_path)
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>ui</html>")
    (dist / "favicon.png").write_bytes(b"\x89PNG")
    return TestClient(create_web_app(registry, dist, replayer))


def test_api_is_open_without_token(tmp_path: Path) -> None:
    assert client(tmp_path).get("/api/sessions").status_code == 200


def test_favicon_served(tmp_path: Path) -> None:
    assert client(tmp_path).get("/favicon.png").content == b"\x89PNG"


def test_index_served(tmp_path: Path) -> None:
    assert client(tmp_path).get("/").text == "<html>ui</html>"


def test_sessions_and_model(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.get("/api/sessions").json() == [{"id": "20261010-120000", "live": False}]
    model = c.get("/api/sessions/20261010-120000/model").json()
    assert len(model["steps"]) == 4
    assert model["live"] is False


def test_unknown_or_traversal_session_is_404(tmp_path: Path) -> None:
    c = client(tmp_path)
    assert c.get("/api/sessions/nope/model").status_code == 404
    assert c.get("/api/sessions/..%2F..%2Fetc/model").status_code == 404


def test_request_detail_and_reveal(tmp_path: Path) -> None:
    c = client(tmp_path)
    model = c.get("/api/sessions/20261010-120000/model").json()
    rid = next(r["id"] for r in model["requests"] if r["url"].endswith("/login"))
    masked = c.get(f"/api/sessions/20261010-120000/requests/{rid}").json()
    revealed = c.get(f"/api/sessions/20261010-120000/requests/{rid}?reveal=true").json()
    assert masked["requestBody"]["form"][1][1] == "••••••"
    assert revealed["requestBody"]["form"][1][1] == "hunter2"
    assert c.get("/api/sessions/20261010-120000/requests/missing").status_code == 404


def test_screenshot_served_as_image(tmp_path: Path) -> None:
    c = client(tmp_path)
    response = c.get("/api/sessions/20261010-120000/screenshots/0")
    assert response.headers["content-type"] == "image/jpeg"
    assert c.get("/api/sessions/20261010-120000/screenshots/9").status_code == 404


def test_live_websocket_sends_model(tmp_path: Path) -> None:
    c = client(tmp_path)
    with c.websocket_connect("/api/sessions/20261010-120000/live") as ws:
        assert len(ws.receive_json()["steps"]) == 4


def test_live_session_pushes_updates_as_events_arrive(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.jsonl")
    registry = Registry(tmp_path)
    registry.add_live("live-1", store)
    c = TestClient(create_web_app(registry, tmp_path / "no-dist"))
    events = session_events()
    with c.websocket_connect("/api/sessions/live-1/live") as ws:
        first = ws.receive_json()
        assert first["live"] is True and len(first["steps"]) == 1
        for e in events[:13]:  # first navigation
            store.append(e)
        assert len(ws.receive_json()["steps"]) == 2
        for e in events[13:]:  # login submit, logout click
            store.append(e)
        assert len(ws.receive_json()["steps"]) == 4
        registry.end_live()
        assert ws.receive_json()["live"] is False


def test_export_zip_download(tmp_path: Path) -> None:
    response = client(tmp_path).get("/api/sessions/20261010-120000/export.zip")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.content[:2] == b"PK"


def test_replay_refuses_unsafe_methods_without_confirmation(tmp_path: Path) -> None:
    server = FakeServer()
    c = client(tmp_path, Replayer(httpx2.Client(transport=httpx2.MockTransport(server))))
    model = c.get("/api/sessions/20261010-120000/model").json()
    rid = next(r["id"] for r in model["requests"] if r["url"].endswith("/login"))
    assert c.post(f"/api/sessions/20261010-120000/requests/{rid}/replay", json={}).status_code == 409
    assert server.calls == []
    ok = c.post(f"/api/sessions/20261010-120000/requests/{rid}/replay", json={"allowUnsafe": True})
    assert ok.status_code == 200
    assert server.calls[0].method == "POST"
    assert server.calls[0].content == b"user=demo&pw=hunter2"


def test_minimize_finds_required_cookie_and_header() -> None:
    server = FakeServer()
    replayer = Replayer(httpx2.Client(transport=httpx2.MockTransport(server)))
    captured = Captured("GET", "https://x.com/api", [["Cookie", "sid=1; _ga=2; theme=dark"], ["Authorization", "Bearer t"],
                                                     ["User-Agent", "UA"], ["Accept", "*/*"], ["Host", "x.com"]], b"")
    result = replayer.minimize(captured)
    assert result["requiredCookies"] == ["sid"]
    assert result["requiredHeaders"] == ["authorization"]
    assert result["unneededCookies"] == ["_ga", "theme"]
    assert all(c.headers["host"] == "x.com" for c in server.calls)  # set by the client, never copied


def test_similar_tolerates_small_size_changes() -> None:
    base = Result(200, 1000, "", [], 0)
    assert similar(base, Result(200, 1030, "", [], 0))
    assert not similar(base, Result(200, 2000, "", [], 0))
    assert not similar(base, Result(403, 1000, "", [], 0))


def test_compare_sessions() -> None:
    a = {"rows": [{"group": "cookie", "domain": "x.com", "name": "sid"}], "requests": [
        {"method": "GET", "url": "https://x.com/a?q=1"}, {"method": "GET", "url": "https://g.com/u", "match": "wire-only"}],
         "blocked": [], "steps": [{"label": "start"}]}  # fmt: skip
    b = {"rows": [{"group": "cookie", "domain": "x.com", "name": "cf_clearance"}], "requests": [
        {"method": "GET", "url": "https://x.com/a"}], "blocked": [{}], "steps": [{"label": "start"}]}  # fmt: skip
    result = compare(a, b)
    assert result["cookies"] == {"onlyA": ["x.com sid"], "onlyB": ["x.com cf_clearance"], "both": []}
    assert result["endpoints"]["both"] == ["GET x.com/a"]
    assert result["blocked"] == {"a": 0, "b": 1}
