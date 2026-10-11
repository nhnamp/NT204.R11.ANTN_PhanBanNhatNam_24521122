"""Decode percent-encoded, form-encoded, and entity-encoded text, and keep the raw value."""

import html
import re
from dataclasses import dataclass, field
from html.entities import html5
from urllib.parse import unquote_to_bytes

INVALID_ESCAPE = re.compile(rb"%(?![0-9A-Fa-f]{2})")
# Only an entity that ends with a semicolon counts: html.unescape also replaces "&lt" without one.
# The digit groups take every digit and strip the zeros in code: a "0*" in the pattern backtracks
# in quadratic time on a long run of zeros.
ENTITY = re.compile(r"&(?:#([0-9]+)|#[xX]([0-9a-fA-F]+)|([A-Za-z][A-Za-z0-9]{1,31}));")
TOO_LARGE = 0x110000
REPLACEMENT = "\ufffd"


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


def decode_entities(text: str) -> Decoding:
    """Replace each complete HTML entity once, and leave everything else as it is."""
    problems: list[str] = []

    def replace(match: re.Match[str]) -> str:
        decimal, hexadecimal, name = match.groups()
        if name is not None:
            # html.unescape would also take a legacy prefix: "&notit;" becomes "¬it;".
            return html5.get(f"{name};", match.group(0))
        number = _code_point(decimal, hexadecimal)
        if number == 0 or 0xD800 <= number <= 0xDFFF or number >= TOO_LARGE:
            if "invalid numeric entity" not in problems:
                problems.append("invalid numeric entity")
            return REPLACEMENT
        # html.unescape maps 0x80-0x9F as a browser does, but it deletes a control character
        # or a noncharacter, which a browser keeps.
        return html.unescape(f"&#{number};") or chr(number)

    value = ENTITY.sub(replace, text)
    return Decoding(value, ["html_entity"] if value != text else [], problems)


def _code_point(decimal: str | None, hexadecimal: str | None) -> int:
    """Read the number of an entity. A browser accepts leading zeros, so "&#0000060;" is "<"."""
    digits = (decimal if decimal is not None else hexadecimal).lstrip("0") or "0"
    base = 10 if decimal is not None else 16
    # int() raises ValueError above 4300 digits, and 0x10FFFF has 7 decimal or 6 hexadecimal digits.
    if len(digits) > (7 if base == 10 else 6):
        return TOO_LARGE
    return int(digits, base)


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
