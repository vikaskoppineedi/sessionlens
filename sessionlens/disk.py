"""Watch the capture profile on disk and report what Chrome persists, without re-reporting values.

Cookie and storage values come from the extension; disk adds only what nothing else shows:
whether a cookie was written to disk, plus disk-only data (cache, history, HSTS, network state, ...).
"""

import json
import logging
import shutil
import sqlite3
import struct
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

Json = dict[str, Any]
Emit = Callable[[Json], None]

_IGNORED_NAMES = {"SingletonLock", "SingletonSocket", "SingletonCookie", "LOCK", "LOG", "LOG.old"}
_COOKIE_DBS = ("Default/Cookies", "Default/Network/Cookies")
_NETWORK_STATE = ("Default/Network Persistent State", "Default/Network/Network Persistent State")
_CACHE_DIR = "Default/Cache/Cache_Data/"
_CACHE_HEADER = struct.Struct("<QIIII")  # magic, version, key length, key hash, padding
_CACHE_MAGIC = 0xFCFB6D1BA7725C30
_MAX_PREF_ITEMS = 100


def read_cache_key(path: Path) -> str | None:
    """Chrome's simple-cache entry files start with a header followed by the cache key (ends with the URL)."""
    try:
        with path.open("rb") as f:
            header = f.read(_CACHE_HEADER.size)
            if len(header) < _CACHE_HEADER.size:
                return None
            magic, _version, key_length, _hash, _pad = _CACHE_HEADER.unpack(header)
            if magic != _CACHE_MAGIC or key_length > 65536:
                return None
            return f.read(key_length).decode("utf-8", "replace")
    except OSError:
        return None


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    if isinstance(value, dict) and value:
        out: dict[str, str] = {}
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: json.dumps(value, sort_keys=True)}


def _query_copy(db: Path, sql: str) -> list[tuple[Any, ...]] | None:
    """Chrome keeps its databases locked, so query a copy (with WAL/journal) instead."""
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp) / db.name
        try:
            shutil.copy2(db, copy)
            for suffix in ("-wal", "-journal"):
                side = db.with_name(db.name + suffix)
                if side.exists():
                    shutil.copy2(side, copy.with_name(copy.name + suffix))
            con = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
            try:
                return con.execute(sql).fetchall()
            finally:
                con.close()
        except (OSError, sqlite3.Error) as error:
            log.debug("skipped %s: %s", db, error)
            return None


class DiskWatcher:
    def __init__(self, profile: Path, emit: Emit) -> None:
        self.profile = profile
        self.emit = emit
        self._files: dict[str, tuple[int, int]] | None = None
        self._cookies: set[tuple[str, str, str]] = set()
        self._history_max_id = 0
        self._json_state: dict[str, Any] = {}

    def _scan(self) -> dict[str, tuple[int, int]]:
        files: dict[str, tuple[int, int]] = {}
        for path in self.profile.rglob("*"):
            if path.name in _IGNORED_NAMES or not path.is_file():
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            files[path.relative_to(self.profile).as_posix()] = (stat.st_size, stat.st_mtime_ns)
        return files

    def _send(self, kind: str, items: list[Json]) -> None:
        if items:
            self.emit({"type": "disk.change", "t": time.time() * 1000, "kind": kind, "items": items})

    def poll(self) -> None:
        current = self._scan()
        first = self._files is None
        previous = self._files or {}
        self._files = current
        changed = {p for p in current if p in previous and current[p] != previous[p]}
        added = set(current) - set(previous)
        removed = set(previous) - set(current)
        touched = changed | added | removed

        # Prime state on the first scan so the baseline profile isn't reported as "changes".
        if first:
            self._read_cookies(report=False)
            self._read_history(report=False)
            self._read_json_files(report=False)
            return

        self._send("files", [
            {"path": p, "change": "added" if p in added else "removed" if p in removed else "modified",
             "size": current.get(p, (0, 0))[0]}
            for p in sorted(touched)
        ])  # fmt: skip
        self._send("cache", [
            {"url": key.rsplit(" ", 1)[-1], "size": current[p][0]}
            for p in sorted(added) if p.startswith(_CACHE_DIR) and (key := read_cache_key(self.profile / p))
        ])  # fmt: skip
        idb: dict[str, str] = {}
        for p in sorted(touched):
            parts = p.split("/")
            if "IndexedDB" in parts and len(parts) > parts.index("IndexedDB") + 1:
                origin = parts[parts.index("IndexedDB") + 1].split(".indexeddb")[0]
                idb.setdefault(origin, "added" if p in added else "modified")
        self._send("indexeddb", [{"origin": o, "change": c} for o, c in idb.items()])
        self._send("serviceworker", [
            {"path": p, "change": "added" if p in added else "removed" if p in removed else "modified"}
            for p in sorted(touched) if "/Service Worker/" in f"/{p}"
        ])  # fmt: skip
        if touched & set(_COOKIE_DBS) or any(p.startswith(_COOKIE_DBS) for p in touched):
            self._read_cookies(report=True)
        if any(p.startswith("Default/History") for p in touched):
            self._read_history(report=True)
        if touched & {"Default/TransportSecurity", "Default/Preferences", *_NETWORK_STATE}:
            self._read_json_files(report=True)

    def _read_cookies(self, report: bool) -> None:
        db = next((self.profile / p for p in _COOKIE_DBS if (self.profile / p).exists()), None)
        if db is None:
            return
        rows = _query_copy(db, "SELECT host_key, name, path, is_persistent, expires_utc FROM cookies")
        if rows is None:
            return
        cookies = [{"host": h, "name": n, "path": p, "persistent": bool(pers), "expires": exp}
                   for h, n, p, pers, exp in rows]  # fmt: skip
        keys = {(c["host"], c["name"], c["path"]) for c in cookies}
        if report:
            self.emit({"type": "disk.cookies", "t": time.time() * 1000, "cookies": cookies})
            self._send("cookies_db", [
                *({"host": h, "name": n, "change": "written"} for h, n, _ in sorted(keys - self._cookies)),
                *({"host": h, "name": n, "change": "deleted"} for h, n, _ in sorted(self._cookies - keys)),
            ])  # fmt: skip
        self._cookies = keys

    def _read_history(self, report: bool) -> None:
        db = self.profile / "Default" / "History"
        if not db.exists():
            return
        rows = _query_copy(db, f"SELECT id, url, title, visit_count FROM urls WHERE id > {self._history_max_id}")
        if rows is None:
            return
        if rows:
            self._history_max_id = max(r[0] for r in rows)
        if report:
            self._send("history", [{"url": u, "title": t, "visits": v} for _, u, t, v in rows])

    def _load_json(self, relative: str) -> Any:
        try:
            return json.loads((self.profile / relative).read_text())
        except (OSError, ValueError):
            return None

    def _read_json_files(self, report: bool) -> None:
        hsts = self._load_json("Default/TransportSecurity")
        if hsts is not None:
            entries = {e.get("host", ""): e for e in hsts.get("sts", [])}
            before = self._json_state.get("hsts", {})
            if report:
                # Chrome stores hostnames hashed (SHA-256), so only the hash and policy are visible.
                self._send("hsts", [
                    {"hostHash": h, "expiry": e.get("expiry"), "includeSubdomains": e.get("sts_include_subdomains")}
                    for h, e in entries.items() if h not in before
                ])  # fmt: skip
            self._json_state["hsts"] = entries

        state = next((self._load_json(p) for p in _NETWORK_STATE if (self.profile / p).exists()), None)
        if state is not None:
            servers = {}
            for s in state.get("net", {}).get("http_server_properties", {}).get("servers", []):
                alt = [a.get("protocol_str") for a in s.get("alternative_service", [])]
                servers[s.get("server", "")] = {"server": s.get("server", ""), "h2": bool(s.get("supports_spdy")),
                                                "h3": "quic" in alt}  # fmt: skip
            before = self._json_state.get("network", {})
            if report:
                self._send("network", [v for k, v in servers.items() if before.get(k) != v])
            self._json_state["network"] = servers

        prefs = self._load_json("Default/Preferences")
        if prefs is not None:
            flat = _flatten(prefs)
            before = self._json_state.get("prefs", {})
            if report and before:
                changes = [
                    {"key": k, "change": "added" if k not in before else "removed" if k not in flat else "changed"}
                    for k in sorted(set(flat) | set(before)) if flat.get(k) != before.get(k)
                ]  # fmt: skip
                self._send("prefs", changes[:_MAX_PREF_ITEMS])
            self._json_state["prefs"] = flat
