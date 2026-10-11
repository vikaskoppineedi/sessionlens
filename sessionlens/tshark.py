"""Turn tshark's decrypted packet JSON into wire events.

Events emitted (all carry t = epoch ms, proto, conn, stream, dir):
  wire.msg   one HTTP message head: method/url (req) or status (resp) + headers; HTTP/1 also has body
  wire.data  one HTTP/2 or HTTP/3 body chunk (base64). replace=True means "full body, drop earlier chunks"

conn + stream identify one request/response exchange:
  h1  conn=tcp:<n>  stream=f<request frame number>  (responses point back via http.request_in)
  h2  conn=tcp:<n>  stream=<h2 stream id>
  h3  conn=quic:<n> stream=<quic stream id>
"""

import base64
import json
import logging
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

Json = dict[str, Any]

# Bodies of these types are counted but not stored: big, and not useful for learning traffic.
_SKIP_BODY_PREFIXES = ("image/", "font/", "video/", "audio/")
_MAX_BODY_BYTES = 5 * 1024 * 1024


_DECODE_ARGS = [
    "-Y", "http || http2.type == 0 || http2.type == 1 || http3",
    "-T", "json", "--no-duplicate-keys",
    "-J", "frame ip ipv6 tcp udp quic http http2 http3",
]  # fmt: skip


def build_tshark_command(tshark: str, interfaces: list[str], keylog: Path, exclude_ports: list[int]) -> list[str]:
    """Live decode. Packets whose TLS keys reach the key log late stay encrypted; the offline pass fixes that."""
    capture_filter = " and ".join(f"not port {p}" for p in exclude_ports)
    argv = [tshark, "-l", "-n", "-f", capture_filter]
    for interface in interfaces:
        argv += ["-i", interface]
    return [*argv, "-o", f"tls.keylog_file:{keylog}", *_DECODE_ARGS]


def build_offline_command(tshark: str, pcap: Path, keylog: Path) -> list[str]:
    """Re-decode the saved capture once every key is in the key log."""
    return [tshark, "-n", "-r", str(pcap), "-o", f"tls.keylog_file:{keylog}", *_DECODE_ARGS]


class PacketSplitter:
    """tshark -T json prints one pretty-printed array; each packet object opens/closes at indent 2.

    Fed line by line so packets are handled while the capture is still running.
    """

    def __init__(self) -> None:
        self._buffer: list[str] = []

    def feed(self, line: str) -> Json | None:
        if line.startswith("  {"):
            self._buffer = [line]
        elif self._buffer and line.rstrip() in ("  }", "  },"):
            text = "".join(self._buffer) + "  }"
            self._buffer = []
            try:
                packet: Json = json.loads(text)
                return packet
            except json.JSONDecodeError:
                log.warning("skipped unparsable tshark packet")
        elif self._buffer:
            self._buffer.append(line)
        return None


def iter_json_packets(lines: Iterator[str]) -> Iterator[Json]:
    splitter = PacketSplitter()
    for line in lines:
        packet = splitter.feed(line)
        if packet is not None:
            yield packet


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _find(obj: Any, key: str) -> list[Any]:
    """All values for key anywhere below obj (tshark nests fields under display-text keys)."""
    found: list[Any] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                found.append(v)
            found.extend(_find(v, key))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_find(item, key))
    return found


def _first(obj: Any, key: str) -> Any:
    values = _find(obj, key)
    return values[0] if values else None


def _hex_to_b64(value: str) -> str:
    return base64.b64encode(bytes.fromhex(value.replace(":", ""))).decode()


def _epoch_ms(frame: Json) -> float:
    raw = frame["frame.time_epoch"]
    try:
        return float(raw) * 1000
    except ValueError:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() * 1000


def _split_headers(raw: list[tuple[str, str]]) -> tuple[dict[str, str], list[list[str]]]:
    pseudo = {n: v for n, v in raw if n.startswith(":")}
    return pseudo, [[n, v] for n, v in raw if not n.startswith(":")]


def _content_type(headers: list[list[str]]) -> str:
    return next((v.lower() for n, v in headers if n.lower() == "content-type"), "")


class WireParser:
    """Stateful: HTTP/2 and HTTP/3 body chunks need to know which side opened the stream."""

    def __init__(self) -> None:
        self._client: dict[tuple[str, str], str] = {}  # (conn, stream) -> client endpoint
        self._skip_body: set[tuple[str, str, str]] = set()  # (conn, stream, dir) of media bodies
        self._body_bytes: dict[tuple[str, str, str], int] = {}

    def parse(self, packet: Json) -> list[Json]:
        layers = packet["_source"]["layers"]
        base = {"t": _epoch_ms(layers["frame"]), "frame": int(layers["frame"]["frame.number"])}
        ip = layers.get("ip") or layers.get("ipv6") or {}
        src_ip = ip.get("ip.src") or ip.get("ipv6.src") or "?"
        events: list[Json] = []
        if "tcp" in layers:
            conn = f"tcp:{layers['tcp']['tcp.stream']}"
            src = f"{src_ip}:{layers['tcp']['tcp.srcport']}"
            for http in _as_list(layers.get("http")):
                events.extend(self._http1(http, conn, base))
            for record in _as_list(layers.get("http2")):
                for frame in _as_list(record.get("http2.stream")):
                    events.extend(self._http2(frame, conn, src, base))
        if "udp" in layers and "http3" in layers:
            number = _first(layers.get("quic"), "quic.connection.number")
            conn = f"quic:{number}"
            src = f"{src_ip}:{layers['udp']['udp.srcport']}"
            for record in _as_list(layers["http3"]):
                for stream in _as_list(record.get("http3.stream")):
                    for frame in _as_list(stream.get("http3.frame")):
                        events.extend(self._http3(frame, conn, src, base))
        return events

    # --- HTTP/1.x: tshark reassembles each message, including the body ---

    def _http1(self, http: Json, conn: str, base: Json) -> list[Json]:
        if "http.request.method" in http or _first(http, "http.request.method"):
            msg = {
                **base, "type": "wire.msg", "proto": "h1", "conn": conn, "stream": f"f{base['frame']}",
                "dir": "req", "method": _first(http, "http.request.method"),
                "url": _first(http, "http.request.full_uri"),
            }  # fmt: skip
            lines = _as_list(http.get("http.request.line"))
        elif _first(http, "http.response.code") is not None:
            msg = {
                **base, "type": "wire.msg", "proto": "h1", "conn": conn,
                "stream": f"f{_first(http, 'http.request_in')}", "dir": "resp",
                "status": int(_first(http, "http.response.code")),
            }  # fmt: skip
            lines = _as_list(http.get("http.response.line"))
        else:
            return []
        msg["headers"] = [[n.strip(), v.strip()] for n, _, v in (line.partition(":") for line in lines) if v]
        # tshark dechunks and decompresses; file_data is the final body, Content-encoded marks it was compressed.
        file_data = http.get("http.file_data")
        if file_data and not _content_type(msg["headers"]).startswith(_SKIP_BODY_PREFIXES):
            msg["body"] = {"b64": _hex_to_b64(file_data), "decoded": True}
        return [msg]

    # --- HTTP/2 and HTTP/3: header frames and data frames per stream ---

    def _headers_msg(
        self, proto: str, conn: str, stream: str, src: str, raw: list[tuple[str, str]], base: Json
    ) -> Json:
        pseudo, headers = _split_headers(raw)
        msg: Json = {**base, "type": "wire.msg", "proto": proto, "conn": conn, "stream": stream, "headers": headers}
        if ":method" in pseudo:
            self._client[(conn, stream)] = src
            msg["dir"] = "req"
            msg["method"] = pseudo[":method"]
            msg["url"] = f"{pseudo.get(':scheme', 'https')}://{pseudo.get(':authority', '')}{pseudo.get(':path', '')}"
        elif ":status" in pseudo:
            msg["dir"] = "resp"
            msg["status"] = int(pseudo[":status"])
        else:
            msg["dir"] = "trailers"
        if _content_type(headers).startswith(_SKIP_BODY_PREFIXES):
            self._skip_body.add((conn, stream, msg["dir"]))
        return msg

    def _data(self, proto: str, conn: str, stream: str, src: str, hex_data: str, base: Json, replace: bool) -> Json:
        direction = "req" if self._client.get((conn, stream)) == src else "resp"
        key = (conn, stream, direction)
        size = len(hex_data.replace(":", "")) // 2
        total = size if replace else self._body_bytes.get(key, 0) + size
        self._body_bytes[key] = total
        event: Json = {
            **base, "type": "wire.data", "proto": proto, "conn": conn, "stream": stream,
            "dir": direction, "len": size, "replace": replace,
        }  # fmt: skip
        if key in self._skip_body or total > _MAX_BODY_BYTES:
            event["skipped"] = True
        else:
            event["b64"] = _hex_to_b64(hex_data)
        return event

    def _http2(self, frame: Json, conn: str, src: str, base: Json) -> list[Json]:
        stream = str(frame.get("http2.streamid"))
        kind = str(frame.get("http2.type"))
        if kind == "1":
            raw = [(h["http2.header.name"], h.get("http2.header.value", ""))
                   for h in _as_list(frame.get("http2.header"))
                   if isinstance(h, dict) and "http2.header.name" in h]  # fmt: skip
            return [self._headers_msg("h2", conn, stream, src, raw, base)] if raw else []
        if kind == "0":
            reassembled = _first(frame.get("http2.body.fragments"), "http2.body.reassembled.data")
            if reassembled:
                return [self._data("h2", conn, stream, src, reassembled, base, replace=True)]
            if frame.get("http2.data.data"):
                return [self._data("h2", conn, stream, src, frame["http2.data.data"], base, replace=False)]
        return []

    def _http3(self, frame: Json, conn: str, src: str, base: Json) -> list[Json]:
        stream = str(frame.get("http3.frame_streamid"))
        kind = int(str(frame.get("http3.frame_type", "-1")), 0)
        if kind == 1:
            raw = [(h["http3.header.header.name"], h.get("http3.headers.header.value", ""))
                   for h in _as_list(frame.get("http3.headers.header"))
                   if isinstance(h, dict) and "http3.header.header.name" in h]  # fmt: skip
            return [self._headers_msg("h3", conn, stream, src, raw, base)] if raw else []
        if kind == 0 and frame.get("http3.data"):
            return [self._data("h3", conn, stream, src, frame["http3.data"], base, replace=False)]
        return []
