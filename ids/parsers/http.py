"""Parse HTTP/1.x requests and responses from one captured payload (RFC 7230)."""

from ids.events import HttpInfo, ParseError

HEADER_LIMIT = 100
HEADER_BYTES_LIMIT = 8192
BODY_PREVIEW_BYTES = 256


def parse_http(payload: bytes) -> tuple[HttpInfo, list[ParseError]]:
    """Parse the start line, the headers, and the body of one HTTP message."""
    head, separator, body = payload.partition(b"\r\n\r\n")
    errors: list[ParseError] = []
    lines = head.split(b"\r\n")
    if len(head) > HEADER_BYTES_LIMIT or len(lines) > HEADER_LIMIT + 1:
        # A crafted payload must not cost unbounded time (R6.4).
        errors.append(
            ParseError(stage="http", type="limit", message="header block exceeds the limit")
        )
        lines = lines[: HEADER_LIMIT + 1]
    start_line = lines[0].decode("iso-8859-1")
    headers = _headers(lines[1:])
    content_length = _content_length(headers)

    first, _, rest = start_line.partition(" ")
    method = target = status_code = reason = None
    version = ""
    if first.startswith("HTTP/"):
        kind = "response"
        version = first
        code, _, text = rest.partition(" ")
        # ISO-8859-1 decodes byte 0xB2 to "²", which isdigit() accepts but int() rejects.
        if code.isdecimal():
            status_code = int(code)
        reason = text or None
    else:
        kind = "request"
        method = first or None
        target, _, version = rest.partition(" ")

    return HttpInfo(
        kind=kind,
        version=version,
        headers=headers,
        body_len=len(body),
        body_preview=body[:BODY_PREVIEW_BYTES].decode("utf-8", errors="replace"),
        body_complete=content_length is None or len(body) >= content_length,
        partial=not separator,
        method=method,
        target=target,
        host=_first(headers.get("host")),
        status_code=status_code,
        reason=reason,
        content_length=content_length,
        content_type=_first(headers.get("content-type")),
    ), errors


def _headers(lines: list[bytes]) -> dict[str, str | list[str]]:
    headers: dict[str, str | list[str]] = {}
    for line in lines:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        key = name.decode("iso-8859-1").strip().lower()
        text = value.decode("iso-8859-1").strip()
        current = headers.get(key)
        if current is None:
            headers[key] = text
        elif isinstance(current, list):
            current.append(text)
        else:
            headers[key] = [current, text]
    return headers


def _first(value: str | list[str] | None) -> str | None:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _content_length(headers: dict[str, str | list[str]]) -> int | None:
    value = _first(headers.get("content-length"))
    if value is None or not value.isdecimal():
        return None
    return int(value)
