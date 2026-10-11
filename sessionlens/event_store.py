import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

Listener = Callable[[], None]


class EventStore:
    """Append-only JSON Lines log: the single source of truth for a capture session.

    Keeps events in memory too, so the analyzer can rebuild its view without re-reading the file.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.events: list[dict[str, Any]] = []
        self._listeners: list[Listener] = []

    @classmethod
    def load(cls, path: Path) -> "EventStore":
        store = cls(path)
        with path.open(encoding="utf-8") as f:
            for line in f:
                try:
                    store.events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # a line cut short by a crash
        return store

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def rewrite(self, events: list[dict[str, Any]]) -> None:
        """Replace the whole log (atomically: a crash leaves either the old or the new file)."""
        tmp = self.path.with_name(self.path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        tmp.replace(self.path)
        self.events = list(events)
        for listener in self._listeners:
            listener()

    def append(self, event: dict[str, Any]) -> None:
        record = {**event, "recv": time.time() * 1000}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.events.append(record)
        for listener in self._listeners:
            listener()
