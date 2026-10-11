"""Cookie header parsing and the matching rules browsers apply (RFC 6265, simplified)."""

from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from ipaddress import ip_address
from urllib.parse import urlsplit


@dataclass
class SetCookie:
    name: str
    value: str
    attrs: dict[str, str] = field(default_factory=dict)  # lower-case keys; flags map to ""

    def deletes(self, now_ms: float) -> bool:
        """Servers delete cookies by setting an expiry in the past."""
        if "max-age" in self.attrs:
            try:
                return int(self.attrs["max-age"]) <= 0
            except ValueError:
                return False
        if "expires" in self.attrs:
            try:
                return parsedate_to_datetime(self.attrs["expires"]).timestamp() * 1000 <= now_ms
            except (TypeError, ValueError):
                return False
        return False


def parse_set_cookie(header: str) -> SetCookie:
    first, *rest = header.split(";")
    name, sep, value = first.partition("=")
    if not sep:
        name, value = "", name
    attrs: dict[str, str] = {}
    for part in rest:
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key:
            val = val.strip()
            attrs[key] = val.lower() if key in ("domain", "samesite") else val
    return SetCookie(name.strip(), value.strip(), attrs)


def parse_cookie_header(header: str) -> list[tuple[str, str]]:
    pairs = []
    for part in header.split(";"):
        part = part.strip()
        if not part:
            continue
        name, sep, value = part.partition("=")
        pairs.append((name.strip(), value.strip()) if sep else ("", name.strip()))
    return pairs


def domain_matches(cookie_domain: str, host: str) -> bool:
    """A leading dot means the cookie also applies to subdomains; otherwise it is host-only."""
    host = host.lower()
    if cookie_domain.startswith("."):
        bare = cookie_domain[1:].lower()
        return host == bare or host.endswith("." + bare)
    return host == cookie_domain.lower()


def path_matches(cookie_path: str, request_path: str) -> bool:
    if request_path == cookie_path or cookie_path == "/":
        return True
    return request_path.startswith(cookie_path.rstrip("/") + "/")


def site_of(host: str) -> str:
    """Approximate "site" (registrable domain): last two labels. Wrong for co.uk-style suffixes."""
    try:
        ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.lower().strip(".").split(".")
    return ".".join(labels[-2:])


def blocked_reason(cookie: SetCookie, url: str, initiator: str | None) -> str:
    """Best guess at why the browser refused a Set-Cookie (Chrome doesn't tell passive observers)."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    secure = "secure" in cookie.attrs
    if cookie.attrs.get("samesite") == "none" and not secure:
        return "SameSite=None requires Secure"
    if secure and parts.scheme == "http" and host not in ("localhost", "127.0.0.1"):
        return "Secure cookie set over plain HTTP"
    if cookie.name.startswith("__Host-") and (
        not secure or "domain" in cookie.attrs or cookie.attrs.get("path") != "/"
    ):
        return "__Host- prefix needs Secure, Path=/ and no Domain"
    if cookie.name.startswith("__Secure-") and not secure:
        return "__Secure- prefix needs Secure"
    domain = cookie.attrs.get("domain")
    if domain and not domain_matches("." + domain.lstrip("."), host):
        return f"Domain attribute ({domain}) doesn't match host {host}"
    if initiator and site_of(urlsplit(initiator).hostname or "") != site_of(host):
        return "Third-party context: Chrome blocks third-party cookies by default"
    return "Unknown (size limit, invalid characters, or browser policy)"
