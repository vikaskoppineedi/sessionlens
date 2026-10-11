import base64
import gzip
import json
from typing import Any

from sessionlens.model import Analysis

T0 = 1_791_000_000_000.0


def cookie(name: str, value: str, domain: str = "www.example.com", **extra: Any) -> dict[str, Any]:
    return {"name": name, "value": value, "domain": domain, "path": "/", "secure": True, "httpOnly": False,
            "sameSite": "lax", "session": True, "hostOnly": not domain.startswith("."), **extra}  # fmt: skip


def hdrs(**pairs: str) -> list[dict[str, str]]:
    return [{"name": k.replace("_", "-"), "value": v} for k, v in pairs.items()]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def session_events() -> list[dict[str, Any]]:
    """Open page (sets sid by header) -> click Login (JS sets theme, server rotates sid, blocked cookie) -> logout."""
    return [
        {"type": "hello", "t": T0, "cookies": [cookie("old", "1")]},
        # Step: typed navigation
        {"type": "nav.commit", "t": T0 + 1000, "tabId": 1, "frameId": 0, "url": "https://www.example.com/",
         "transitionType": "typed", "transitionQualifiers": ["from_address_bar"]},
        {"type": "req.start", "t": T0 + 990, "requestId": "1", "url": "https://www.example.com/", "method": "GET",
         "resourceType": "main_frame", "tabId": 1, "frameId": 0, "initiator": None, "body": None},
        {"type": "req.headers", "t": T0 + 995, "requestId": "1", "headers": hdrs(Cookie="old=1", User_Agent="UA")},
        {"type": "resp.headers", "t": T0 + 1100, "requestId": "1", "statusCode": 200, "statusLine": "HTTP/1.1 200",
         "headers": hdrs(Set_Cookie="sid=anon; Path=/; Secure")},
        {"type": "cookie.change", "t": T0 + 1101, "removed": False, "cause": "explicit", "cookie": cookie("sid", "anon")},
        {"type": "req.done", "t": T0 + 1150, "requestId": "1", "statusCode": 200, "fromCache": False},
        {"type": "wire.msg", "t": T0 + 1010, "proto": "h2", "conn": "tcp:1", "stream": "1", "dir": "req", "method": "GET",
         "url": "https://www.example.com/", "headers": [["cookie", "old=1"], ["user-agent", "UA"]]},
        {"type": "wire.msg", "t": T0 + 1090, "proto": "h2", "conn": "tcp:1", "stream": "1", "dir": "resp", "status": 200,
         "headers": [["set-cookie", "sid=anon; Path=/; Secure"], ["content-type", "application/json"],
                     ["content-encoding", "gzip"]]},
        {"type": "wire.data", "t": T0 + 1095, "proto": "h2", "conn": "tcp:1", "stream": "1", "dir": "resp",
         "b64": b64(gzip.compress(b'{"hello": "world"}')), "len": 30, "replace": False},
        # Chrome background request only the wire sees
        {"type": "wire.msg", "t": T0 + 1200, "proto": "h2", "conn": "tcp:2", "stream": "1", "dir": "req", "method": "GET",
         "url": "https://update.googleapis.com/check", "headers": []},
        {"type": "storage", "t": T0 + 1300, "area": "local", "origin": "https://www.example.com", "tabId": 1,
         "items": {"first_visit": "1"}},
        {"type": "screenshot", "t": T0 + 1800, "tabId": 1, "url": "https://www.example.com/", "dataUrl": "data:image/jpeg;base64,AA=="},
        # Step: click Login, form POST
        {"type": "action", "t": T0 + 5000, "action": "submit", "selector": "form", "formAction": "https://www.example.com/login",
         "formMethod": "post", "fields": [{"name": "user", "type": "text", "value": "demo"},
                                          {"name": "pw", "type": "password", "value": "[redacted]"}], "tabId": 1, "frameId": 0},
        {"type": "req.start", "t": T0 + 5010, "requestId": "2", "url": "https://www.example.com/login", "method": "POST",
         "resourceType": "main_frame", "tabId": 1, "frameId": 0, "initiator": "https://www.example.com",
         "body": {"formData": {"user": ["demo"], "pw": ["hunter2"]}}},
        {"type": "req.headers", "t": T0 + 5011, "requestId": "2", "headers": hdrs(Cookie="old=1; sid=anon")},
        {"type": "resp.headers", "t": T0 + 5100, "requestId": "2", "statusCode": 303, "statusLine": "HTTP/1.1 303",
         "headers": [{"name": "Set-Cookie", "value": "sid=user42; Path=/; Secure; HttpOnly"},
                     {"name": "Set-Cookie", "value": "track=1; SameSite=None"},
                     {"name": "Set-Cookie", "value": "old=; Max-Age=0"}]},
        {"type": "cookie.change", "t": T0 + 5101, "removed": True, "cause": "overwrite", "cookie": cookie("sid", "anon")},
        {"type": "cookie.change", "t": T0 + 5101, "removed": False, "cause": "explicit",
         "cookie": cookie("sid", "user42", httpOnly=True)},
        {"type": "cookie.change", "t": T0 + 5102, "removed": True, "cause": "expired_overwrite", "cookie": cookie("old", "1")},
        {"type": "req.redirect", "t": T0 + 5101, "requestId": "2", "statusCode": 303,
         "redirectUrl": "https://www.example.com/home"},
        {"type": "req.start", "t": T0 + 5110, "requestId": "2", "url": "https://www.example.com/home", "method": "GET",
         "resourceType": "main_frame", "tabId": 1, "frameId": 0, "initiator": "https://www.example.com", "body": None},
        {"type": "nav.commit", "t": T0 + 5300, "tabId": 1, "frameId": 0, "url": "https://www.example.com/home",
         "transitionType": "form_submit", "transitionQualifiers": ["server_redirect"]},
        {"type": "cookie.change", "t": T0 + 5600, "removed": False, "cause": "explicit", "cookie": cookie("theme", "dark")},
        {"type": "storage", "t": T0 + 5700, "area": "local", "origin": "https://www.example.com", "tabId": 1,
         "items": {"first_visit": "1", "token": "eyJ"}},
        {"type": "disk.cookies", "t": T0 + 9000, "cookies": [
            {"host": "www.example.com", "name": "sid", "path": "/", "persistent": True, "expires": 0}]},
        # Step: click logout
        {"type": "action", "t": T0 + 20000, "action": "click", "selector": "button#logout", "tag": "button",
         "text": "Log out", "tabId": 1, "frameId": 0},
        {"type": "cookie.change", "t": T0 + 20100, "removed": True, "cause": "explicit", "cookie": cookie("theme", "dark")},
        {"type": "storage", "t": T0 + 20200, "area": "local", "origin": "https://www.example.com", "tabId": 1,
         "items": {"first_visit": "2"}},
    ]  # fmt: skip


def model() -> dict[str, Any]:
    return Analysis(session_events()).model()


def row(m: dict[str, Any], row_id: str) -> dict[str, Any]:
    return next(r for r in m["rows"] if r["id"] == row_id)


def states(r: dict[str, Any]) -> list[str]:
    return [c["state"] for c in r["cells"]]


def test_steps_merge_navigation_into_triggering_action() -> None:
    steps = model()["steps"]
    assert [s["kind"] for s in steps] == ["start", "nav", "action", "action"]
    assert "typed" in steps[1]["label"]
    assert steps[2]["label"].startswith("submit POST /login")
    assert steps[2]["url"] == "https://www.example.com/home"
    assert steps[3]["label"] == 'click "Log out"'
    assert steps[1]["screenshot"] == 0
    assert steps[2]["screenshot"] is None


def test_requests_split_redirect_hops_and_assign_steps() -> None:
    reqs = {r["url"]: r for r in model()["requests"]}
    assert reqs["https://www.example.com/"]["step"] == 1
    assert reqs["https://www.example.com/login"]["status"] == 303
    assert reqs["https://www.example.com/login"]["redirectTo"] == "https://www.example.com/home"
    assert reqs["https://www.example.com/home"]["step"] == 2


def test_wire_matching() -> None:
    reqs = {r["url"]: r for r in model()["requests"]}
    assert reqs["https://www.example.com/"]["match"] == "matched"
    assert reqs["https://www.example.com/"]["proto"] == "h2"
    assert reqs["https://www.example.com/login"]["match"] == "ext-only"
    background = reqs["https://update.googleapis.com/check"]
    assert background["match"] == "wire-only"
    assert background["browserInternal"] is True


def test_cookie_cells_follow_jar_per_step() -> None:
    m = model()
    assert states(row(m, "c|www.example.com|/|old")) == ["same", "same", "removed", "absent"]
    assert row(m, "c|www.example.com|/|old")["initial"] == "1"
    assert row(m, "c|www.example.com|/|sid")["initial"] is None
    assert states(row(m, "c|www.example.com|/|sid")) == ["absent", "added", "changed", "same"]
    sid = row(m, "c|www.example.com|/|sid")
    assert sid["cells"][2]["value"] == "user42"
    assert sid["cells"][3].get("value") is None
    assert states(row(m, "c|www.example.com|/|theme")) == ["absent", "absent", "added", "removed"]


def test_cookie_lineage_header_vs_javascript() -> None:
    m = model()
    reqs = {r["id"]: r for r in m["requests"]}
    sid_sets = row(m, "c|www.example.com|/|sid")["setBy"]
    assert [s["source"] for s in sid_sets] == ["header", "header"]
    assert reqs[sid_sets[1]["request"]]["url"] == "https://www.example.com/login"
    theme_sets = row(m, "c|www.example.com|/|theme")["setBy"]
    assert theme_sets[0]["source"] == "javascript"
    assert theme_sets[0]["request"] is None


def test_cookie_sent_by_requests() -> None:
    m = model()
    reqs = {r["id"]: r for r in m["requests"]}
    sent = [reqs[i]["url"] for i in row(m, "c|www.example.com|/|sid")["sentBy"]]
    assert sent == ["https://www.example.com/login"]
    assert "c|www.example.com|/|sid" in reqs[row(m, "c|www.example.com|/|sid")["sentBy"][0]]["cookiesSent"]


def test_blocked_cookie_inferred() -> None:
    m = model()
    blocked = m["blocked"]
    assert [b["name"] for b in blocked] == ["track"]
    assert "requires Secure" in blocked[0]["reason"]


def test_badges_and_persistence() -> None:
    m = model()
    sid = row(m, "c|www.example.com|/|sid")
    assert set(sid["badges"]) == {"ext", "wire", "disk"}
    assert sid["persistence"]["onDisk"] is True
    theme = row(m, "c|www.example.com|/|theme")
    assert theme["persistence"]["onDisk"] is False


def test_storage_rows() -> None:
    m = model()
    assert states(row(m, "local|https://www.example.com|first_visit")) == ["absent", "added", "same", "changed"]
    assert states(row(m, "local|https://www.example.com|token")) == ["absent", "absent", "added", "removed"]


def test_detail_decodes_gzip_json_response() -> None:
    analysis = Analysis(session_events())
    rid = next(r["id"] for r in analysis.model()["requests"] if r["url"] == "https://www.example.com/")
    detail = analysis.detail(rid)
    assert detail["responseBody"]["kind"] == "json"
    assert detail["responseBody"]["json"] == {"hello": "world"}
    assert detail["requestHeaders"]["wire"] == [["cookie", "old=1"], ["user-agent", "UA"]]


def test_detail_redacts_password_fields_unless_revealed() -> None:
    analysis = Analysis(session_events())
    rid = next(r["id"] for r in analysis.model()["requests"] if r["url"].endswith("/login"))
    body = analysis.detail(rid)["requestBody"]
    assert body["form"] == [["user", "demo"], ["pw", "••••••"]]
    assert analysis.detail(rid, reveal=True)["requestBody"]["form"][1] == ["pw", "hunter2"]


def test_detail_set_cookie_outcomes() -> None:
    analysis = Analysis(session_events())
    rid = next(r["id"] for r in analysis.model()["requests"] if r["url"].endswith("/login"))
    outcomes = {c["name"]: c["outcome"] for c in analysis.detail(rid)["cookiesSet"]}
    assert outcomes == {"sid": "stored", "track": "blocked", "old": "deleted"}


def test_unknown_request_detail_raises() -> None:
    try:
        Analysis([]).detail("nope")
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_empty_session_has_start_step() -> None:
    m = Analysis([]).model()
    assert len(m["steps"]) == 1
    assert m["rows"] == [] and m["requests"] == []


def test_early_hints_response_is_not_the_final_response() -> None:
    events = session_events()
    hints = {"type": "wire.msg", "t": T0 + 1050, "proto": "h2", "conn": "tcp:1", "stream": "1", "dir": "resp",
             "status": 103, "headers": [["link", "</app.css>; rel=preload"]]}
    events.insert(8, hints)  # before the 200 response on the same stream
    analysis = Analysis(events)
    rid = next(r["id"] for r in analysis.model()["requests"] if r["url"] == "https://www.example.com/")
    detail = analysis.detail(rid)
    assert detail["status"] == 200
    assert detail["responseBody"]["json"] == {"hello": "world"}
    assert [c["name"] for c in detail["cookiesSet"]] == ["sid"]


def test_wire_reset_replaces_live_wire_events() -> None:
    events = session_events()
    live_only = {"type": "wire.msg", "t": T0 + 1500, "proto": "h2", "conn": "tcp:9", "stream": "1", "dir": "req",
                 "method": "GET", "url": "https://live-only.example/", "headers": []}
    final = {"type": "wire.msg", "t": T0 + 1600, "proto": "h2", "conn": "tcp:8", "stream": "1", "dir": "req",
             "method": "GET", "url": "https://final.example/", "headers": []}
    events += [live_only, {"type": "wire.reset", "t": T0 + 30000}, final]
    urls = {r["url"] for r in Analysis(events).model()["requests"]}
    assert "https://final.example/" in urls
    assert "https://live-only.example/" not in urls
    assert "https://www.example.com/login" in urls  # extension events survive the reset


def test_model_is_json_serialisable() -> None:
    json.dumps(model())
