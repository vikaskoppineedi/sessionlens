from sessionlens.cookies import (
    blocked_reason,
    domain_matches,
    parse_cookie_header,
    parse_set_cookie,
    path_matches,
    site_of,
)


def test_parse_set_cookie_attributes_case_insensitive() -> None:
    parsed = parse_set_cookie("sid=a=b; Path=/app; DOMAIN=.Example.com; HttpOnly; secure; SameSite=None; Max-Age=60")
    assert parsed.name == "sid"
    assert parsed.value == "a=b"
    assert parsed.attrs == {
        "path": "/app",
        "domain": ".example.com",
        "httponly": "",
        "secure": "",
        "samesite": "none",
        "max-age": "60",
    }


def test_parse_set_cookie_without_value_or_name() -> None:
    assert parse_set_cookie("flag").name == ""
    assert parse_set_cookie("flag").value == "flag"
    assert parse_set_cookie("  =x ").name == ""


def test_set_cookie_deletes_when_max_age_zero_or_expired() -> None:
    assert parse_set_cookie("a=; Max-Age=0").deletes(now_ms=0) is True
    assert parse_set_cookie("a=; Expires=Thu, 01 Jan 1970 00:00:00 GMT").deletes(now_ms=1_000) is True
    assert parse_set_cookie("a=1; Max-Age=10").deletes(now_ms=0) is False
    assert parse_set_cookie("a=1; Expires=garbage").deletes(now_ms=0) is False


def test_parse_cookie_header_keeps_order_and_unicode() -> None:
    assert parse_cookie_header("a=1; b=x=y;  ключ=значение ;bare") == [
        ("a", "1"),
        ("b", "x=y"),
        ("ключ", "значение"),
        ("", "bare"),
    ]
    assert parse_cookie_header("") == []


def test_domain_matching() -> None:
    assert domain_matches(".example.com", "www.example.com")
    assert domain_matches(".example.com", "example.com")
    assert domain_matches("example.com", "example.com")
    assert not domain_matches("example.com", "www.example.com")  # host-only cookie
    assert not domain_matches(".example.com", "badexample.com")


def test_path_matching() -> None:
    assert path_matches("/", "/anything")
    assert path_matches("/app", "/app/page")
    assert path_matches("/app", "/app")
    assert not path_matches("/app", "/apple")


def test_site_of_uses_last_two_labels() -> None:
    assert site_of("a.b.example.com") == "example.com"
    assert site_of("localhost") == "localhost"
    assert site_of("127.0.0.1") == "127.0.0.1"


def test_blocked_reasons() -> None:
    url = "https://www.example.com/x"
    assert "requires Secure" in blocked_reason(parse_set_cookie("a=1; SameSite=None"), url, None)
    assert "plain HTTP" in blocked_reason(parse_set_cookie("a=1; Secure"), "http://example.com/", None)
    assert "Domain" in blocked_reason(parse_set_cookie("a=1; Domain=other.com"), url, None)
    assert "__Host-" in blocked_reason(parse_set_cookie("__Host-a=1; Secure; Path=/; Domain=example.com"), url, None)
    assert "__Secure-" in blocked_reason(parse_set_cookie("__Secure-a=1"), url, None)
    assert "Third-party" in blocked_reason(parse_set_cookie("a=1; Secure; SameSite=None"), url, "https://news.site")
    assert "Unknown" in blocked_reason(parse_set_cookie("a=1"), url, "https://www.example.com")
