"""Decode percent-encoded, form-encoded, and entity-encoded text, and keep the raw value."""

import html
import re
from dataclasses import dataclass, field
from html.entities import html5
from urllib.parse import unquote_to_bytes

from ids.stages.mime import decode_mime, decode_text

INVALID_ESCAPE = re.compile(rb"%(?![0-9A-Fa-f]{2})")
# Only an entity that ends with a semicolon counts: html.unescape also replaces "&lt" without one.
# The digit groups take every digit and strip the zeros in code: a "0*" in the pattern backtracks
# in quadratic time on a long run of zeros.
ENTITY = re.compile(r"&(?:#([0-9]+)|#[xX]([0-9a-fA-F]+)|([A-Za-z][A-Za-z0-9]{1,31}));")
TOO_LARGE = 0x110000
REPLACEMENT = "\ufffd"
HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")
FORM_TYPE = "application/x-www-form-urlencoded"
# Text uses TAB, LF, and CR, so they do not count as control bytes of a binary payload.
CONTROL_BYTES = bytes(byte for byte in (*range(0x20), 0x7F) if byte not in (0x09, 0x0A, 0x0D))


@dataclass
class Decoding:
    value: str
    methods: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class _Payload:
    data: bytes = b""
    not_hex: bool = False
    cut: bool = False
    error: dict | None = None


def decode_record(record: dict, payload_limit: int) -> dict:
    """Return the decoding fields of one record. A missing or mistyped field gives no item."""
    protocol = _upper(record.get("app_protocol"))
    if protocol == "DNS":
        return _result([], [])
    payload = _read_payload(record, payload_limit)
    items = []
    if protocol == "HTTP":
        items.extend(_http_items(record, payload, payload_limit))
    elif _is_tcp(record) and payload.data:
        items.extend(
            _item(mime.field_name, mime.methods, mime.value, mime.problems, payload_limit, mime.failed)
            for mime in decode_mime(payload.data, payload.cut)
        )
    payload_item = _payload_item(payload, payload_limit)
    if payload_item is not None:
        items.append(payload_item)
    return _result(items, [payload.error] if payload.error else [])


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


def decode_form(text: str) -> Decoding:
    raw = text.encode("utf-8")
    decoded = decode_percent(raw, form=True)
    value, problems = _utf8(decoded)
    if INVALID_ESCAPE.search(raw):
        problems.insert(0, "invalid percent escape")
    return Decoding(value, ["form"] if decoded != raw else [], problems)


def _read_payload(record: dict, limit: int) -> _Payload:
    text, from_preview = record.get("payload_hex"), False
    if not isinstance(text, str):
        text, from_preview = record.get("payload_preview"), True
    if not isinstance(text, str):
        return _Payload()
    # Cut the text before the conversion, so a huge payload_hex is never converted whole.
    cut_here = len(text) > 2 * limit
    text = text[: 2 * limit]
    if not HEX.fullmatch(text):
        return _Payload(not_hex=True)
    data = bytes.fromhex(text)
    length = record.get("payload_len")
    known = isinstance(length, int) and not isinstance(length, bool)
    cut = cut_here or (known and len(data) < length)
    error = None
    if cut:
        where = "to the preview" if from_preview else "at the payload limit"
        size = f"{len(data)} of {length} bytes" if known else f"{len(data)} bytes"
        error = {"stage": "decoder", "type": "limit", "message": f"payload cut {where} ({size})"}
    return _Payload(data, False, cut, error)


def _http_items(record: dict, payload: _Payload, limit: int) -> list[dict]:
    application = record.get("application")
    if not isinstance(application, dict):
        application = {}
    items = []
    target = application.get("target")
    if isinstance(target, str):
        decoding = decode_target(target)
        if decoding.methods or decoding.problems:
            items.append(_item("http.target", decoding.methods, decoding.value, decoding.problems, limit))
    body = _body_item(application, payload, limit)
    if body is not None:
        items.append(body)
    return items


def _body_item(application: dict, payload: _Payload, limit: int) -> dict | None:
    # parse_http splits at the same place, but its body_preview is cut and has lost the bad bytes.
    _, separator, body = payload.data.partition(b"\r\n\r\n")
    media = _media_type(application.get("content_type") or _header(application, "content-type"))
    is_text = media is None or media == FORM_TYPE or media.startswith("text/")
    if not separator or not is_text or _is_compressed(application):
        return None
    text, invalid = decode_text(body, final=not payload.cut)
    decoding = decode_form(text) if media == FORM_TYPE else Decoding(text)
    entities = decode_entities(decoding.value)
    problems = decoding.problems + entities.problems
    if entities.value == text and not problems:
        return None
    if invalid:
        problems.append("invalid UTF-8 in body")
    # Only a literal False counts: a record without the key must not look cut.
    if application.get("body_complete") is False:
        problems.append("body continues in a later segment")
    if payload.cut:
        problems.append("payload cut")
    return _item("http.body", decoding.methods + entities.methods, entities.value, problems, limit)


def _payload_item(payload: _Payload, limit: int) -> dict | None:
    if payload.not_hex:
        return _item("payload", [], None, ["payload is not hex"], limit)
    data = payload.data
    text, invalid = decode_text(data, final=not payload.cut)
    problems = []
    if invalid == 0:
        if data.isascii():
            return None
    else:
        control = len(data) - len(data.translate(None, CONTROL_BYTES))
        if (control + invalid) * 4 > len(data):
            text = None
            problems.append("binary payload")
        else:
            problems.append(f"invalid UTF-8: {invalid} invalid sequence{'' if invalid == 1 else 's'} replaced")
    if payload.cut:
        problems.append("payload cut")
    return _item("payload", ["charset:utf-8"] if text is not None else [], text, problems, limit)


def _item(
    field: str, methods: list[str], value: str | None, problems: list[str], limit: int, failed: bool = False
) -> dict:
    if value is not None and len(value) > limit:
        value = value[:limit]
        problems = [*problems, f"value cut at {limit} characters"]
    return {
        "field": field,
        "methods": methods,
        "value": value,
        "status": "failed" if failed else "partial" if problems else "ok",
        "reason": "; ".join(problems) or None,
    }


def _result(items: list[dict], errors: list[dict]) -> dict:
    statuses = {item["status"] for item in items}
    if not items:
        status = "not_applicable"
    elif statuses == {"ok"}:
        status = "ok"
    elif statuses == {"failed"}:
        status = "failed"
    else:
        status = "partial"
    return {"decode_status": status, "decoded": items, "processing_errors": errors}


def _is_tcp(record: dict) -> bool:
    transport = record.get("transport")
    return isinstance(transport, dict) and _upper(transport.get("protocol")) == "TCP"


def _upper(value: object) -> str:
    return value.upper() if isinstance(value, str) else ""


def _media_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    return value.split(";")[0].strip().lower() or None


def _header(application: dict, name: str) -> object:
    """Look a header up without regard to case: an events file can hold any spelling."""
    headers = application.get("headers")
    if not isinstance(headers, dict):
        return None
    return next((value for key, value in headers.items() if isinstance(key, str) and key.lower() == name), None)


def _is_compressed(application: dict) -> bool:
    value = _header(application, "content-encoding")
    values = value if isinstance(value, list) else [value]
    return any(isinstance(item, str) and item.strip().lower() not in ("", "identity") for item in values)


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
