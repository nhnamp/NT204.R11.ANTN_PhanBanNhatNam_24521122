"""Decode percent-encoded, form-encoded, and entity-encoded text, and keep the raw value."""

import re
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes

INVALID_ESCAPE = re.compile(rb"%(?![0-9A-Fa-f]{2})")


@dataclass
class Decoding:
    value: str
    methods: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def decode_percent(data: bytes, form: bool) -> bytes:
    # The plus sign must become a space first, so that %2B stays a plus sign.
    return unquote_to_bytes(data.replace(b"+", b" ") if form else data)


def decode_target(target: str) -> Decoding:
    """Decode a request target once: percent in the path, form in the query."""
    raw = _target_bytes(target)
    path, question, query = raw.partition(b"?")
    decoded_path = decode_percent(path, form=False)
    decoded_query = decode_percent(query, form=True)

    value, problems = _utf8(decoded_path + question + decoded_query)
    if INVALID_ESCAPE.search(raw):
        problems.insert(0, "invalid percent escape")

    methods = []
    if decoded_path != path:
        methods.append("percent")
    if decoded_query != query:
        methods.append("form")
    if not methods and value != target:
        methods.append("charset:utf-8")
    return Decoding(value, methods, problems)


def _target_bytes(target: str) -> bytes:
    """Return the bytes that the target came from.

    The HTTP parser reads the request line as ISO-8859-1, so the latin-1 bytes are the bytes of the
    packet. They count only when they are valid UTF-8. Otherwise the text came from an events file
    and is meant as it stands: a hand-written "é" must not become the invalid byte 0xE9.
    """
    try:
        candidate = target.encode("latin-1")
        candidate.decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return target.encode("utf-8")
    return candidate


def _utf8(data: bytes) -> tuple[str, list[str]]:
    try:
        return data.decode("utf-8"), []
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), ["invalid UTF-8"]
