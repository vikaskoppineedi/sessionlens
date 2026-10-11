import json
import sqlite3
import struct
from pathlib import Path
from typing import Any

from sessionlens.disk import DiskWatcher, read_cache_key


def make_cookies_db(path: Path, rows: list[tuple[str, str, str, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS cookies (host_key TEXT, name TEXT, path TEXT, is_persistent INTEGER, "
                "expires_utc INTEGER, encrypted_value BLOB)")  # fmt: skip
    con.execute("DELETE FROM cookies")
    con.executemany("INSERT INTO cookies VALUES (?, ?, ?, ?, 0, x'00')", rows)
    con.commit()
    con.close()


def make_history_db(path: Path, urls: list[tuple[str, str, int]]) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    con.executemany("INSERT INTO urls (url, title, visit_count) VALUES (?, ?, ?)", urls)
    con.commit()
    con.close()


def cache_entry(path: Path, key: str) -> None:
    raw = key.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<QIIII", 0xFCFB6D1BA7725C30, 5, len(raw), 0, 0) + raw + b"\x00" * 50)


class Recorder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def __call__(self, event: dict[str, Any]) -> None:
        self.events.append(event)

    def kinds(self) -> dict[str, list[Any]]:
        out: dict[str, list[Any]] = {}
        for e in self.events:
            if e["type"] == "disk.change":
                out.setdefault(e["kind"], []).extend(e["items"])
        return out


def test_first_poll_is_silent_baseline(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    (tmp_path / "Default" / "Preferences").write_text("{}")
    rec = Recorder()
    DiskWatcher(tmp_path, rec).poll()
    assert rec.events == []


def test_file_changes_reported_and_lock_files_ignored(tmp_path: Path) -> None:
    default = tmp_path / "Default"
    default.mkdir()
    (default / "a.txt").write_text("1")
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    (default / "a.txt").write_text("22")
    (default / "b.txt").write_text("x")
    (tmp_path / "SingletonLock").write_text("x")
    watcher.poll()
    files = {(f["path"], f["change"]) for f in rec.kinds()["files"]}
    assert files == {("Default/a.txt", "modified"), ("Default/b.txt", "added")}


def test_cookie_db_reports_persistence_without_values(tmp_path: Path) -> None:
    db = tmp_path / "Default" / "Cookies"
    make_cookies_db(db, [])
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    make_cookies_db(db, [(".example.com", "sid", "/", 1)])
    watcher.poll()
    snapshot = [e for e in rec.events if e["type"] == "disk.cookies"][-1]
    assert snapshot["cookies"] == [{"host": ".example.com", "name": "sid", "path": "/", "persistent": True, "expires": 0}]
    assert "value" not in json.dumps(snapshot)
    assert rec.kinds()["cookies_db"] == [{"host": ".example.com", "name": "sid", "change": "written"}]


def test_history_reports_new_urls_only(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    db = tmp_path / "Default" / "History"
    make_history_db(db, [("https://a.com/", "A", 1)])
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    make_history_db(db, [("https://b.com/", "B", 1)])
    watcher.poll()
    assert rec.kinds()["history"] == [{"url": "https://b.com/", "title": "B", "visits": 1}]


def test_cache_entries_show_url(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    cache_entry(tmp_path / "Default/Cache/Cache_Data/abc_0", "1/0/_dk_https://x.com https://x.com https://x.com/app.js")
    watcher.poll()
    assert rec.kinds()["cache"] == [{"url": "https://x.com/app.js", "size": 24 + 56 + 50}]


def test_read_cache_key_rejects_garbage(tmp_path: Path) -> None:
    bad = tmp_path / "bad_0"
    bad.write_bytes(b"short")
    assert read_cache_key(bad) is None


def test_network_state_lists_http3_servers(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    state = tmp_path / "Default" / "Network Persistent State"
    state.write_text(json.dumps({"net": {"http_server_properties": {"servers": []}}}))
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    servers = [{"server": "https://x.com", "supports_spdy": True,
                "alternative_service": [{"protocol_str": "quic", "port": 443}]}]  # fmt: skip
    state.write_text(json.dumps({"net": {"http_server_properties": {"servers": servers}}}))
    watcher.poll()
    assert rec.kinds()["network"] == [{"server": "https://x.com", "h2": True, "h3": True}]


def test_preferences_diff_lists_changed_keys(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    prefs = tmp_path / "Default" / "Preferences"
    prefs.write_text(json.dumps({"a": {"b": 1}, "c": 2}))
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    prefs.write_text(json.dumps({"a": {"b": 5}, "d": 1}))
    watcher.poll()
    assert sorted(rec.kinds()["prefs"], key=lambda i: i["key"]) == [
        {"key": "a.b", "change": "changed"},
        {"key": "c", "change": "removed"},
        {"key": "d", "change": "added"},
    ]


def test_indexeddb_and_service_worker_grouped(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    idb = tmp_path / "Default/IndexedDB/https_x.com_0.indexeddb.leveldb"
    idb.mkdir(parents=True)
    (idb / "000003.log").write_text("x")
    sw = tmp_path / "Default/Service Worker/ScriptCache"
    sw.mkdir(parents=True)
    (sw / "index").write_text("x")
    watcher.poll()
    kinds = rec.kinds()
    assert kinds["indexeddb"] == [{"origin": "https_x.com_0", "change": "added"}]
    assert kinds["serviceworker"] == [{"path": "Default/Service Worker/ScriptCache/index", "change": "added"}]


def test_unreadable_sqlite_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "Default").mkdir()
    rec = Recorder()
    watcher = DiskWatcher(tmp_path, rec)
    watcher.poll()
    (tmp_path / "Default" / "Cookies").write_bytes(b"not a database")
    watcher.poll()
    assert not [e for e in rec.events if e["type"] == "disk.cookies"]
