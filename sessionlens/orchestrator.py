"""`sessionlens start`: launch everything in order, prove each piece works, then say "start browsing"."""

import asyncio
import contextlib
import os
import secrets
import shutil
import socket
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI

from sessionlens import config
from sessionlens.chrome import build_chrome_command
from sessionlens.disk import DiskWatcher
from sessionlens.event_store import EventStore
from sessionlens.export import write_export
from sessionlens.ingest import create_ingest_app
from sessionlens.model import prune_unmatched_wire
from sessionlens.session import create_session_dir, profile_in_use, restore_pristine, save_pristine
from sessionlens.tshark import PacketSplitter, WireParser, build_offline_command, build_tshark_command
from sessionlens.web import Registry, create_web_app

OK, FAIL, WARN = "✅", "❌", "⚠️ "
# tshark prints a body as one hex line; asyncio's default 64 KB line limit would kill the reader.
TSHARK_LINE_LIMIT = 64 * 1024 * 1024


@dataclass
class Check:
    name: str
    ok: bool
    fix: str = ""


def preflight(
    which: Callable[[str], str | None] = shutil.which,
    can_capture: Callable[[], bool] = lambda: os.access("/dev/bpf0", os.R_OK | os.W_OK),
    exists: Callable[[str], bool] = os.path.exists,
) -> list[Check]:
    return [
        Check("tshark installed", which("tshark") is not None, "brew install wireshark"),
        Check("Packet capture permission", can_capture(),
              "brew install --cask wireshark-chmodbpf, then log out and back in (or restart)"),
        Check("Google Chrome installed", exists(config.CHROME_PATH), "Install Google Chrome in /Applications"),
        Check("Analyzer UI built", exists(str(config.WEB_DIST_DIR / "index.html")),
              "cd web && npm install && npm run build"),
    ]  # fmt: skip


def lan_ip() -> str | None:
    """The address other laptops on the Wi-Fi can reach. UDP connect sends no packets."""
    with contextlib.suppress(OSError), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("192.0.2.1", 9))
        address: str = s.getsockname()[0]
        return address
    return None


def claim_url(nonce: str) -> str:
    """Start page of the capture Chrome. Its nonce tells the server which browser's extension to trust."""
    return f"http://{config.INGEST_HOST}:{config.INGEST_PORT}/claim?nonce={nonce}"


def say(mark: str, text: str) -> None:
    print(f"  {mark} {text}", flush=True)


async def _serve(app: FastAPI, host: str, port: int) -> tuple[uvicorn.Server, asyncio.Task[None]]:
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    deadline = time.monotonic() + 10
    while not server.started:
        if task.done() or time.monotonic() > deadline:
            raise RuntimeError(f"could not listen on {host}:{port} (is another sessionlens running?)")
        await asyncio.sleep(0.05)
    return server, task


async def _stop(server: uvicorn.Server, task: asyncio.Task[None]) -> None:
    server.should_exit = True
    with contextlib.suppress(Exception):
        await asyncio.wait_for(task, 5)


async def _wait_for(predicate: Callable[[], bool], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.2)
    return predicate()


async def _launch_chrome(profile: Path, keylog: Path | None, urls: list[str]) -> asyncio.subprocess.Process:
    argv, env = build_chrome_command(config.CHROME_PATH, profile, keylog, urls)
    return await asyncio.create_subprocess_exec(
        *argv, env=env, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
    )


async def setup_profile() -> None:
    """One time: a fresh capture profile, the user loads the extension, we save it as pristine."""
    print("\nFirst run: set up the capture profile (once).")
    shutil.rmtree(config.CAPTURE_PROFILE_DIR, ignore_errors=True)
    config.CAPTURE_PROFILE_DIR.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmp:
        store = EventStore(Path(tmp) / "setup.jsonl")
        nonce = secrets.token_urlsafe(16)
        server, task = await _serve(create_ingest_app(store, config.EXTENSION_ORIGIN, nonce), config.INGEST_HOST,
                                    config.INGEST_PORT)  # fmt: skip
        chrome = await _launch_chrome(config.CAPTURE_PROFILE_DIR, None, [claim_url(nonce), "chrome://extensions"])
        print(
            "  In the Chrome window that opened:\n"
            "    1. Turn on 'Developer mode' (top right)\n"
            f"    2. Click 'Load unpacked' and choose {config.EXTENSION_DIR}\n"
            "  Waiting for the extension to connect…",
            flush=True,
        )
        connected = await _wait_until_hello_or_exit(store, chrome)
        if connected:
            say(OK, "Extension installed. Now quit that Chrome window (Cmd+Q).")
            await chrome.wait()
        await _stop(server, task)
    if not connected:
        raise SystemExit(f"{FAIL} Chrome closed before the extension connected. Run sessionlens start again.")
    save_pristine(config.CAPTURE_PROFILE_DIR, config.PRISTINE_PROFILE_DIR)
    say(OK, "Pristine profile saved. You won't need to do this again.\n")


async def _wait_until_hello_or_exit(store: EventStore, chrome: asyncio.subprocess.Process) -> bool:
    while chrome.returncode is None:
        if any(e["type"] == "hello" for e in store.events):
            return True
        await asyncio.sleep(0.3)
    return any(e["type"] == "hello" for e in store.events)


class Capture:
    """tshark (live decode) + dumpcap (pcapng archive you can open in Wireshark later)."""

    def __init__(self, session: Path, store: EventStore) -> None:
        self.session = session
        self.store = store
        self.capturing = asyncio.Event()
        self.stderr: list[str] = []
        self.procs: list[asyncio.subprocess.Process] = []
        self.tasks: list[asyncio.Task[None]] = []

    async def start(self) -> None:
        keylog = self.session / "keys.log"
        ports = [config.INGEST_PORT, config.UI_PORT]
        argv = build_tshark_command("tshark", config.CAPTURE_INTERFACES, keylog, ports)
        pipe = asyncio.subprocess.PIPE
        tshark = await asyncio.create_subprocess_exec(*argv, stdout=pipe, stderr=pipe, limit=TSHARK_LINE_LIMIT)
        self.procs.append(tshark)
        self.tasks += [asyncio.create_task(self._read_packets(tshark)), asyncio.create_task(self._read_stderr(tshark))]
        capture_filter = " and ".join(f"not port {p}" for p in ports)
        interfaces = [arg for i in config.CAPTURE_INTERFACES for arg in ("-i", i)]
        dumpcap = await asyncio.create_subprocess_exec(
            "dumpcap", "-q", "-f", capture_filter, *interfaces, "-w", str(self.session / "capture.pcapng"),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
        self.procs.append(dumpcap)

    async def _read_packets(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stdout is not None
        splitter, parser = PacketSplitter(), WireParser()
        async for raw in proc.stdout:
            packet = splitter.feed(raw.decode("utf-8", "replace"))
            if packet is None:
                continue
            try:
                events = parser.parse(packet)
            except (KeyError, ValueError, TypeError) as error:
                self.stderr.append(f"parse error: {error}")
                continue
            for event in events:
                self.store.append(event)

    async def _read_stderr(self, proc: asyncio.subprocess.Process) -> None:
        assert proc.stderr is not None
        async for raw in proc.stderr:
            line = raw.decode("utf-8", "replace").strip()
            self.stderr = [*self.stderr[-20:], line]
            if line.startswith("Capturing on"):
                self.capturing.set()

    async def stop(self) -> None:
        await asyncio.sleep(1.5)  # let the last packets drain
        for proc in self.procs:
            if proc.returncode is None:
                proc.terminate()
        for proc in self.procs:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), 5)
        for task in self.tasks:
            task.cancel()

    async def finalize(self) -> int:
        """Decode the whole pcap again now that every TLS key is logged; replaces the live wire events."""
        pcap = self.session / "capture.pcapng"
        if not pcap.exists():
            return -1
        argv = build_offline_command("tshark", pcap, self.session / "keys.log")
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=TSHARK_LINE_LIMIT
        )
        assert proc.stdout is not None
        splitter, parser = PacketSplitter(), WireParser()
        events: list[dict[str, Any]] = []
        async for raw in proc.stdout:
            packet = splitter.feed(raw.decode("utf-8", "replace"))
            if packet is not None:
                with contextlib.suppress(KeyError, ValueError, TypeError):
                    events.extend(parser.parse(packet))
        await proc.wait()
        self.store.append({"type": "wire.reset", "t": time.time() * 1000})
        for event in events:
            self.store.append(event)
        return sum(1 for e in events if e["type"] == "wire.msg")


async def _watch_disk(watcher: DiskWatcher, store: EventStore, stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()

    def emit(event: dict[str, Any]) -> None:
        loop.call_soon_threadsafe(store.append, event)

    watcher.emit = emit
    while not stop.is_set():
        await asyncio.to_thread(watcher.poll)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), config.DISK_POLL_SECONDS)
    await asyncio.to_thread(watcher.poll)  # one last look after Chrome quits and flushes


def _status(store: EventStore, component: str, ok: bool, detail: str) -> None:
    store.append({"type": "capture.status", "t": time.time() * 1000, "component": component, "ok": ok,
                  "detail": detail})  # fmt: skip


async def start() -> None:
    print("sessionlens: checking prerequisites")
    checks = preflight()
    for check in checks:
        say(OK if check.ok else FAIL, check.name + ("" if check.ok else f"  →  {check.fix}"))
    if not all(c.ok for c in checks):
        raise SystemExit(1)
    if profile_in_use(config.CAPTURE_PROFILE_DIR):
        raise SystemExit(f"{FAIL} The capture Chrome is still open. Quit it (Cmd+Q) and run again.")
    if not config.PRISTINE_PROFILE_DIR.is_dir():
        await setup_profile()

    print("sessionlens: starting")
    restore_pristine(config.PRISTINE_PROFILE_DIR, config.CAPTURE_PROFILE_DIR)
    say(OK, "Capture profile reset to pristine (no cookies, cache or history)")
    session = create_session_dir(config.SESSIONS_DIR, datetime.now())
    keylog = session / "keys.log"
    keylog.touch(mode=0o600)
    store = EventStore(session / "events.jsonl")
    nonce = secrets.token_urlsafe(16)
    registry = Registry(config.SESSIONS_DIR)
    registry.add_live(session.name, store)

    servers = [
        await _serve(create_ingest_app(store, config.EXTENSION_ORIGIN, nonce), config.INGEST_HOST, config.INGEST_PORT),
        await _serve(create_web_app(registry, config.WEB_DIST_DIR), config.UI_HOST, config.UI_PORT),
    ]
    say(OK, f"Analyzer server listening on port {config.UI_PORT}")

    capture = Capture(session, store)
    await capture.start()
    if not await _wait_for(capture.capturing.is_set, 15):
        say(FAIL, "tshark did not start capturing:\n      " + "\n      ".join(capture.stderr[-5:]))
        raise SystemExit(1)
    say(OK, f"tshark capturing on {', '.join(config.CAPTURE_INTERFACES)}")
    _status(store, "tshark", True, f"capturing {', '.join(config.CAPTURE_INTERFACES)}")

    stop_disk = asyncio.Event()
    watcher = DiskWatcher(config.CAPTURE_PROFILE_DIR, store.append)
    disk_task = asyncio.create_task(_watch_disk(watcher, store, stop_disk))

    chrome = await _launch_chrome(config.CAPTURE_PROFILE_DIR, keylog, [claim_url(nonce)])
    say(OK, "Chrome launched (separate window, your normal Chrome is untouched)")

    if await _wait_for(lambda: any(e["type"] == "hello" for e in store.events), 30):
        say(OK, "Extension connected")
        _status(store, "extension", True, "connected")
    else:
        say(FAIL, "Extension did not connect. In the capture window open chrome://extensions and check that "
                  "'SessionLens' is on. Capture continues without it.")  # fmt: skip
        _status(store, "extension", False, "not connected")
    if await _wait_for(lambda: keylog.stat().st_size > 0, 20):
        say(OK, "TLS keys being logged")
    else:
        say(WARN, "No TLS keys yet (they appear on the first HTTPS connection)")
    if await _wait_for(lambda: any(e["type"] == "wire.msg" for e in store.events), 20):
        say(OK, "Decryption working (seen Chrome's own background requests)")
    else:
        say(WARN, "No decrypted traffic yet; it should appear once you browse")

    ip = lan_ip()
    print(f"\n  Analyzer:  http://localhost:{config.UI_PORT}/")
    if ip:
        print(f"  From another laptop on this Wi-Fi:  http://{ip}:{config.UI_PORT}/")
    print(f"  Session folder: {session}  (contains passwords and tokens: never share it)")
    print("\n  👉 Start browsing in the new Chrome window. Quit it (Cmd+Q) when done.\n", flush=True)

    try:
        await chrome.wait()
        print("Chrome closed. Finishing capture…", flush=True)
    finally:
        if chrome.returncode is None:
            chrome.terminate()
        stop_disk.set()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(disk_task, 10)
        await capture.stop()
        _status(store, "tshark", False, "stopped")

    print("Re-decoding the full capture with the complete key log…", flush=True)
    live_count = sum(1 for e in store.events if e["type"] == "wire.msg")
    final_count = await capture.finalize()
    if final_count >= 0:
        say(OK, f"Wire messages: {live_count} decoded live, {final_count} after the full pass")
    before = len(store.events)
    store.rewrite(prune_unmatched_wire(store.events))
    dropped = before - len(store.events)
    say(OK, f"Kept browser traffic only (dropped {dropped} events from other apps / Chrome background)")
    say(OK, f"Export written: {write_export(session)}")
    registry.end_live()
    say(OK, f"Saved {len(store.events)} events to {session}")
    print(f"  Analyzer still running: http://localhost:{config.UI_PORT}/  (Ctrl+C to quit)", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for server, task in servers:
            await _stop(server, task)


async def view() -> None:
    """Browse saved sessions without capturing."""
    server, task = await _serve(create_web_app(Registry(config.SESSIONS_DIR), config.WEB_DIST_DIR),
                                config.UI_HOST, config.UI_PORT)  # fmt: skip
    ip = lan_ip()
    print(f"Analyzer: http://localhost:{config.UI_PORT}/")
    if ip:
        print(f"From another laptop: http://{ip}:{config.UI_PORT}/")
    print("Ctrl+C to quit.", flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await _stop(server, task)
