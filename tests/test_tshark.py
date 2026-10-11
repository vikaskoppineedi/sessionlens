import base64
import json
from pathlib import Path
from typing import Any

from sessionlens.tshark import WireParser, build_tshark_command, iter_json_packets

FIXTURE = Path(__file__).parent / "fixtures" / "tshark_packets.json"


def parse_fixture() -> list[dict[str, Any]]:
    parser = WireParser()
    events: list[dict[str, Any]] = []
    for packet in json.loads(FIXTURE.read_text()):
        events.extend(parser.parse(packet))
    return events


def messages(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if e["type"] == "wire.msg"]


def header(msg: dict[str, Any], name: str) -> list[str]:
    return [v for n, v in msg["headers"] if n.lower() == name]


def test_http1_request_and_response_pair_by_request_frame() -> None:
    msgs = [m for m in messages(parse_fixture()) if m["proto"] == "h1"]
    request, response = msgs
    assert request["dir"] == "req"
    assert request["method"] == "GET"
    assert request["url"].startswith("http://clients2.google.com/time/1/current?")
    assert header(request, "host") == ["clients2.google.com"]
    assert response["dir"] == "resp"
    assert response["status"] == 200
    assert response["stream"] == request["stream"]
    assert response["conn"] == request["conn"]


def test_http1_body_is_decoded_by_tshark() -> None:
    response = [m for m in messages(parse_fixture()) if m["proto"] == "h1" and m["dir"] == "resp"][0]
    body = base64.b64decode(response["body"]["b64"])
    assert response["body"]["decoded"] is True
    assert body.startswith(b")]}'")  # Google's anti-JSON-hijacking prefix


def test_http2_set_cookie_redirect() -> None:
    msgs = [m for m in messages(parse_fixture()) if m["proto"] == "h2"]
    request = next(m for m in msgs if m["dir"] == "req" and "cookies/set" in m["url"])
    response = next(m for m in msgs if m["dir"] == "resp" and m["stream"] == request["stream"])
    assert request["method"] == "GET"
    assert request["url"] == "https://httpbin.org/cookies/set?session_id=abc123"
    assert not any(n.startswith(":") for n, _ in request["headers"])
    assert response["status"] == 302
    assert any("session_id=abc123" in v for v in header(response, "set-cookie"))


def test_http2_follow_up_request_sends_cookie() -> None:
    msgs = [m for m in messages(parse_fixture()) if m["proto"] == "h2" and m["dir"] == "req"]
    follow_up = next(m for m in msgs if m["url"] == "https://httpbin.org/cookies")
    assert header(follow_up, "cookie") == ["session_id=abc123"]


def test_http2_data_chunks_belong_to_response() -> None:
    events = parse_fixture()
    chunks = [e for e in events if e["type"] == "wire.data" and e["proto"] == "h2"]
    assert chunks
    assert all(c["dir"] == "resp" for c in chunks)
    assert any(base64.b64decode(c["b64"]).startswith(b"<!DOCTYPE") for c in chunks)


def test_http3_request_and_response() -> None:
    msgs = [m for m in messages(parse_fixture()) if m["proto"] == "h3"]
    request = next(m for m in msgs if m["dir"] == "req")
    assert request["method"] == "GET"
    assert request["url"] == "https://www.cloudflare.com/"
    assert request["conn"] == "quic:0"
    response = next(m for m in msgs if m["dir"] == "resp" and m["stream"] == request["stream"])
    assert response["status"] == 200


def test_every_message_has_epoch_ms_time() -> None:
    for msg in messages(parse_fixture()):
        assert 1.7e12 < msg["t"] < 2e12


def test_iter_json_packets_splits_streaming_output() -> None:
    packets = [{"_source": {"layers": {"frame": {"frame.number": str(i)}}}} for i in range(3)]
    text = json.dumps(packets, indent=2)
    parsed = list(iter_json_packets(iter(text.splitlines(keepends=True))))
    assert [p["_source"]["layers"]["frame"]["frame.number"] for p in parsed] == ["0", "1", "2"]


def test_iter_json_packets_skips_garbage() -> None:
    lines = ["[\n", "  {\n", '    "broken": \n', "  },\n", "  {\n", '    "ok": 1\n', "  }\n", "]\n"]
    assert list(iter_json_packets(iter(lines))) == [{"ok": 1}]


def test_build_tshark_command_reads_keylog_and_excludes_own_ports(tmp_path: Path) -> None:
    argv = build_tshark_command("tshark", ["en0", "lo0"], tmp_path / "keys.log", [8765, 8080])
    joined = " ".join(argv)
    assert f"tls.keylog_file:{tmp_path / 'keys.log'}" in joined
    assert argv.count("-i") == 2
    assert "not port 8765 and not port 8080" in argv
    assert "-l" in argv and "json" in argv
