"""Analyzer HTTP/WebSocket API plus the built UI. No authentication: anyone on the network can read it."""

import asyncio
import base64
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sessionlens.compare import compare
from sessionlens.event_store import EventStore
from sessionlens.export import export_zip
from sessionlens.model import Analysis
from sessionlens.replay import Replayer

Json = dict[str, Any]
PUSH_DEBOUNCE_S = 0.4


@dataclass
class SessionEntry:
    store: EventStore
    live: bool
    cached_version: int = -1
    cached: Analysis | None = None
    # One per open live WebSocket, with the loop it waits on (events may be appended from any thread).
    waiters: set[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = field(default_factory=set)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def notify(self) -> None:
        for loop, waiter in list(self.waiters):
            loop.call_soon_threadsafe(waiter.set)

    def analysis(self) -> Analysis:
        with self.lock:  # several viewers may ask at once; build once per new batch of events
            version = len(self.store.events)
            if self.cached is None or version != self.cached_version:
                self.cached = Analysis(self.store.events[:version])
                self.cached_version = version
            return self.cached

    def model(self) -> Json:
        return {**self.analysis().model(), "live": self.live}


class Registry:
    """Saved sessions load lazily from sessions/<id>/events.jsonl; the live one is shared with capture."""

    def __init__(self, sessions_dir: Path) -> None:
        self.sessions_dir = sessions_dir
        self.entries: dict[str, SessionEntry] = {}
        self.live_id: str | None = None

    def add_live(self, session_id: str, store: EventStore) -> None:
        entry = SessionEntry(store, live=True)
        self.entries[session_id] = entry
        self.live_id = session_id
        store.subscribe(entry.notify)

    def end_live(self) -> None:
        if self.live_id and self.live_id in self.entries:
            self.entries[self.live_id].live = False
            self.entries[self.live_id].notify()

    def list(self) -> list[Json]:
        ids = {p.parent.name for p in self.sessions_dir.glob("*/events.jsonl")} | set(self.entries)
        return [{"id": i, "live": i in self.entries and self.entries[i].live} for i in sorted(ids, reverse=True)]

    def get(self, session_id: str) -> SessionEntry:
        if session_id not in self.entries:
            path = self.sessions_dir / session_id / "events.jsonl"
            if "/" in session_id or ".." in session_id or not path.is_file():
                raise HTTPException(404, "no such session")
            self.entries[session_id] = SessionEntry(EventStore.load(path), live=False)
        return self.entries[session_id]


class ReplayBody(BaseModel):
    dropHeaders: list[str] = []
    dropCookies: list[str] = []
    allowUnsafe: bool = False


def create_web_app(registry: Registry, dist_dir: Path, replayer: Replayer | None = None) -> FastAPI:
    app = FastAPI()
    replay_client = replayer or Replayer()


    @app.get("/api/sessions")
    def sessions() -> list[Json]:
        return registry.list()

    @app.get("/api/sessions/{session_id}/model")
    def model(session_id: str) -> Json:
        return registry.get(session_id).model()

    @app.get("/api/sessions/{session_id}/requests/{request_id}")
    def detail(session_id: str, request_id: str, reveal: bool = False) -> Json:
        try:
            return registry.get(session_id).analysis().detail(request_id, reveal=reveal)
        except KeyError:
            raise HTTPException(404, "no such request") from None

    @app.get("/api/sessions/{session_id}/screenshots/{index}")
    def screenshot(session_id: str, index: int) -> Response:
        shots = registry.get(session_id).analysis().screenshots
        if not 0 <= index < len(shots):
            raise HTTPException(404, "no such screenshot")
        header, _, data = shots[index]["dataUrl"].partition(",")
        media = header.removeprefix("data:").split(";")[0] or "image/jpeg"
        return Response(base64.b64decode(data), media_type=media, headers={"cache-control": "max-age=31536000"})

    def captured(session_id: str, request_id: str) -> Any:
        try:
            return registry.get(session_id).analysis().captured(request_id)
        except KeyError:
            raise HTTPException(404, "no such request") from None

    @app.post("/api/sessions/{session_id}/requests/{request_id}/replay")
    def replay(session_id: str, request_id: str, body: ReplayBody) -> Json:
        try:
            result = replay_client.send(captured(session_id, request_id), set(body.dropHeaders),
                                        set(body.dropCookies), body.allowUnsafe)  # fmt: skip
        except PermissionError as error:
            raise HTTPException(409, str(error)) from None
        except Exception as error:  # network errors are results, not crashes
            return {"error": f"{type(error).__name__}: {error}"}
        return result.json()

    @app.post("/api/sessions/{session_id}/requests/{request_id}/minimize")
    def minimize(session_id: str, request_id: str, body: ReplayBody) -> Json:
        try:
            return replay_client.minimize(captured(session_id, request_id), body.allowUnsafe)
        except PermissionError as error:
            raise HTTPException(409, str(error)) from None
        except Exception as error:
            return {"error": f"{type(error).__name__}: {error}"}

    @app.get("/api/sessions/{session_id}/export.zip")
    def download_export(session_id: str) -> Response:
        data = export_zip(registry.get(session_id).analysis(), session_id, dist_dir)
        headers = {"content-disposition": f'attachment; filename="sessionlens-{session_id}.zip"'}
        return Response(data, media_type="application/zip", headers=headers)

    @app.get("/api/compare")
    def compare_sessions(a: str = Query(...), b: str = Query(...)) -> Json:
        return compare(registry.get(a).analysis().model(), registry.get(b).analysis().model())

    @app.websocket("/api/sessions/{session_id}/live")
    async def live(ws: WebSocket, session_id: str) -> None:
        try:
            entry = registry.get(session_id)
        except HTTPException:
            await ws.close(code=1008)
            return
        await ws.accept()
        waiter = (asyncio.get_running_loop(), asyncio.Event())
        entry.waiters.add(waiter)
        try:
            while True:
                # Building the view is CPU work; a thread keeps the event loop free to receive capture events.
                await ws.send_json(await asyncio.to_thread(entry.model))
                if not entry.live:
                    await ws.receive_text()  # finished session: nothing more to push; wait for close
                    continue
                await waiter[1].wait()
                await asyncio.sleep(PUSH_DEBOUNCE_S)  # batch bursts of events into one push
                waiter[1].clear()
        except WebSocketDisconnect:
            pass
        finally:
            entry.waiters.discard(waiter)

    if (dist_dir / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist_dir / "assets"), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(dist_dir / "index.html")

        @app.get("/favicon.png")
        def favicon() -> FileResponse:
            return FileResponse(dist_dir / "favicon.png")
    else:

        @app.get("/")
        def missing_ui() -> Response:
            return Response("UI not built. Run: cd web && npm install && npm run build", media_type="text/plain")

    return app
