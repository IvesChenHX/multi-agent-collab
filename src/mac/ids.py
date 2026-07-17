from __future__ import annotations

import re
import secrets
import threading
import time

_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_IDENTIFIER = re.compile(r"^(?P<prefix>[A-Z]+)-(?P<ulid>[0-9A-HJKMNP-TV-Z]{26})(?:-[a-z0-9][a-z0-9-]{0,63})?$")
_LOCK = threading.Lock()
_LAST_TIMESTAMP_MS = -1
_LAST_RANDOM = -1


def _encode(value: int, length: int) -> str:
    chars = ["0"] * length
    for index in range(length - 1, -1, -1):
        value, remainder = divmod(value, 32)
        chars[index] = _ALPHABET[remainder]
    if value:
        raise ValueError("value does not fit requested base32 length")
    return "".join(chars)


def ulid(*, timestamp_ms: int | None = None) -> str:
    """Return a process-monotonic, Crockford Base32 ULID."""
    global _LAST_RANDOM, _LAST_TIMESTAMP_MS
    with _LOCK:
        current = int(time.time_ns() // 1_000_000) if timestamp_ms is None else timestamp_ms
        if current < 0 or current >= 2**48:
            raise ValueError("ULID timestamp must fit 48 bits")
        current = max(current, _LAST_TIMESTAMP_MS)
        if current == _LAST_TIMESTAMP_MS:
            random_part = _LAST_RANDOM + 1
            if random_part >= 2**80:
                current += 1
                random_part = secrets.randbits(80)
        else:
            random_part = secrets.randbits(80)
        _LAST_TIMESTAMP_MS, _LAST_RANDOM = current, random_part
        return _encode(current, 10) + _encode(random_part, 16)


def _slug(value: str) -> str:
    parts = re.findall(r"[a-z0-9]+", value.lower().replace("_", "-"))
    return "-".join(parts)[:64].strip("-")


def prefixed(prefix: str, slug: str | None = None) -> str:
    normalized_prefix = prefix.upper()
    if not normalized_prefix.isalpha() or not normalized_prefix.isascii():
        raise ValueError("identifier prefix must contain ASCII letters only")
    value = f"{normalized_prefix}-{ulid()}"
    normalized_slug = _slug(slug) if slug else ""
    return f"{value}-{normalized_slug}" if normalized_slug else value


def is_identifier(value: str, prefix: str | None = None) -> bool:
    match = _IDENTIFIER.fullmatch(value)
    return bool(match and (prefix is None or match.group("prefix") == prefix.upper()))
