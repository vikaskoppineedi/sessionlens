"""Decode HTTP bodies for display: undo Content-Encoding, then classify as form / JSON / text / binary."""

import json
import zlib
from typing import Any
from urllib.parse import parse_qsl

import brotli
import zstandard

MAX_TEXT_CHARS = 500_000
REDACTED = "••••••"
# Field names that hold credentials: passwords, security-question answers (kba = knowledge-based auth),
# one-time codes.
_SECRET_WORDS = ("password", "passwd", "pwd", "kba", "answer", "otp_", "_otp", "passcode", "secret")


def decompress(data: bytes, encoding: str) -> tuple[bytes, str | None]:
    """Returns (bytes, error). Unknown or broken encodings return the input unchanged plus an error."""
    try:
        for coding in reversed([c.strip().lower() for c in encoding.split(",") if c.strip()]):
            if coding in ("gzip", "x-gzip"):
                data = zlib.decompress(data, 16 + zlib.MAX_WBITS)
            elif coding == "deflate":
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    data = zlib.decompress(data, -zlib.MAX_WBITS)  # raw deflate, common in the wild
            elif coding == "br":
                data = brotli.decompress(data)
            elif coding == "zstd":
                data = zstandard.ZstdDecompressor().decompressobj().decompress(data)
            elif coding != "identity":
                return data, f"unsupported encoding {coding}"
    except (zlib.error, brotli.error, zstandard.ZstdError) as error:
        return data, f"could not decode {encoding}: {error}"
    return data, None


def _is_secret(name: str, secret_names: set[str]) -> bool:
    lowered = name.lower()
    return lowered in secret_names or any(word in lowered for word in _SECRET_WORDS) or lowered == "otp"


def _redact_json(value: Any, secret_names: set[str]) -> Any:
    if isinstance(value, dict):
        return {k: REDACTED if _is_secret(k, secret_names) else _redact_json(v, secret_names) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json(v, secret_names) for v in value]
    return value


def describe(data: bytes, content_type: str, secret_names: set[str] | None = None) -> dict[str, Any]:
    """secret_names: field names to mask (password inputs seen on forms). None disables masking."""
    secrets = secret_names if secret_names is not None else set()
    redact = secret_names is not None
    result: dict[str, Any] = {"size": len(data), "contentType": content_type}
    if not data:
        return {**result, "kind": "none"}
    ctype = content_type.lower()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {**result, "kind": "binary", "hexPreview": data[:256].hex(" ")}
    if "x-www-form-urlencoded" in ctype:
        pairs = parse_qsl(text, keep_blank_values=True)
        return {**result, "kind": "form",
                "form": [[k, REDACTED if redact and _is_secret(k, secrets) else v] for k, v in pairs]}  # fmt: skip
    stripped = text.lstrip()
    if "json" in ctype or stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(text)
            return {**result, "kind": "json", "json": _redact_json(parsed, secrets) if redact else parsed}
        except json.JSONDecodeError:
            pass
    return {**result, "kind": "text", "text": text[:MAX_TEXT_CHARS], "truncated": len(text) > MAX_TEXT_CHARS}


def describe_form_data(form: dict[str, list[str]], secret_names: set[str] | None) -> dict[str, Any]:
    """webRequest already parsed this multipart/urlencoded body into {name: [values]}."""
    redact = secret_names is not None
    secrets = secret_names or set()
    pairs = [[k, REDACTED if redact and _is_secret(k, secrets) else v] for k, values in form.items() for v in values]
    return {"kind": "form", "form": pairs, "size": sum(len(k) + len(v) for k, v in pairs), "contentType": "form"}
