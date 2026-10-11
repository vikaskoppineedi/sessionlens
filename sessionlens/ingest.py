import json
import logging
import secrets
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from sessionlens.event_store import EventStore

log = logging.getLogger(__name__)

# Events a connection may send before it proves it is the capture browser (hello + startup burst).
MAX_UNCLAIMED_EVENTS = 50_000

CLAIM_PAGE = """<!doctype html><meta charset="utf-8"><title>sessionlens capture window</title>
<body style="font:16px -apple-system,sans-serif;background:#0f1115;color:#d8dde6;padding:40px">
<h2>sessionlens capture window</h2>
<p>This Chrome is being recorded. Type the site's address in the bar above and browse.</p>
<p style="color:#8b93a3">Quit this window (Cmd+Q) when you are done.</p></body>"""


def create_ingest_app(store: EventStore, allowed_origin: str, nonce: str) -> FastAPI:
    """Accept events only from the extension running in the capture Chrome.

    The extension may also be installed in other Chrome profiles; those connect too, with the same
    origin. Only the capture Chrome was launched on /claim?nonce=<this session's nonce>, so a
    connection's events are kept only after it sends that nonce back.
    """
    app = FastAPI()

    @app.get("/claim")
    def claim_page() -> HTMLResponse:
        return HTMLResponse(CLAIM_PAGE)

    @app.websocket("/ingest")
    async def ingest(ws: WebSocket) -> None:
        # WebSockets skip CORS, so any page on this machine could connect; only our extension may.
        if ws.headers.get("origin") != allowed_origin:
            await ws.close(code=1008)
            return
        await ws.accept()
        pending: list[dict[str, Any]] = []
        claimed = False
        try:
            while True:
                text = await ws.receive_text()
                try:
                    event = json.loads(text)
                except json.JSONDecodeError:
                    log.warning("dropped non-JSON message: %.80s", text)
                    continue
                kind = event.get("type")
                if kind == "ping":
                    continue
                if kind == "claim":
                    if not secrets.compare_digest(str(event.get("nonce", "")), nonce):
                        await ws.close(code=1008)
                        return
                    claimed = True
                    for buffered in pending:
                        store.append(buffered)
                    pending.clear()
                elif claimed:
                    store.append(event)
                elif len(pending) < MAX_UNCLAIMED_EVENTS:
                    pending.append(event)
        except WebSocketDisconnect:
            pass

    return app
