"""Detect the application protocol from the payload; the port is only a hint (R5.2)."""

from ids.events import AppProtocol, Detection, TransportInfo
from ids.parsers.dns import read_name

PORT_HINTS: dict[int, AppProtocol] = {
    80: "HTTP",
    8080: "HTTP",
    8000: "HTTP",
    8888: "HTTP",
    53: "DNS",
    5353: "DNS",
    25: "SMTP",
    587: "SMTP",
    2525: "SMTP",
}

HTTP_METHODS = (
    b"GET",
    b"POST",
    b"PUT",
    b"DELETE",
    b"HEAD",
    b"OPTIONS",
    b"PATCH",
    b"TRACE",
    b"CONNECT",
)
HTTP_VERSIONS = (b"HTTP/1.0", b"HTTP/1.1")
SMTP_COMMANDS = (
    b"HELO",
    b"EHLO",
    b"MAIL",
    b"RCPT",
    b"DATA",
    b"RSET",
    b"NOOP",
    b"QUIT",
    b"VRFY",
    b"EXPN",
    b"HELP",
    b"AUTH",
    b"STARTTLS",
)

DNS_HEADER_LEN = 12
DNS_MAX_OPCODE = 2
DNS_MAX_QUESTION_COUNT = 16
DNS_MAX_RECORD_COUNT = 64


def detect_app_protocol(transport: TransportInfo | None, payload: bytes) -> Detection:
    """Decide the application protocol from the payload, then from the port."""
    hint = _port_hint(transport)
    if not payload:
        if hint is None:
            return Detection(protocol="UNKNOWN", method="none", confidence="low", rule="")
        return Detection(protocol=hint, method="port", confidence="low", rule="port_hint")
    found = _first_match(payload, transport, hint)
    if found is None:
        return Detection(protocol="UNKNOWN", method="none", confidence="low", rule="")
    protocol, rule = found
    method = "port+payload" if hint == protocol else "payload"
    return Detection(protocol=protocol, method=method, confidence="high", rule=rule)


def _first_match(
    payload: bytes, transport: TransportInfo | None, hint: AppProtocol | None
) -> tuple[AppProtocol, str] | None:
    """Apply the payload rules in order, because the first match wins (R5.3)."""
    if _is_http_request(payload):
        return "HTTP", "http_request"
    if _is_http_response(payload):
        return "HTTP", "http_response"
    if _is_smtp_response(payload, hint):
        return "SMTP", "smtp_response"
    if _is_smtp_command(payload):
        return "SMTP", "smtp_command"
    if transport is None:
        return None
    if transport.protocol == "TCP" and _is_dns_tcp(payload):
        return "DNS", "dns_tcp"
    if transport.protocol == "UDP" and _is_dns_udp(payload):
        return "DNS", "dns_udp"
    return None


def _port_hint(transport: TransportInfo | None) -> AppProtocol | None:
    if transport is None:
        return None
    for port in (transport.dst_port, transport.src_port):
        if port in PORT_HINTS:
            return PORT_HINTS[port]
    return None


def _first_line(payload: bytes) -> tuple[bytes, bool]:
    """Split off the first line. The flag is true when CRLF ended it."""
    index = payload.find(b"\n")
    if index < 0:
        return payload, False
    if index and payload[index - 1] == 0x0D:
        return payload[: index - 1], True
    return payload[:index], False


def _is_http_request(payload: bytes) -> bool:
    line, _ = _first_line(payload)
    method, separator, rest = line.partition(b" ")
    if not separator or method not in HTTP_METHODS:
        return False
    target, separator, version = rest.partition(b" ")
    if not separator or not target:
        return False
    # A captured segment can end inside the version, so accept a consistent prefix.
    return any(candidate.startswith(version) for candidate in HTTP_VERSIONS)


def _is_http_response(payload: bytes) -> bool:
    line, _ = _first_line(payload)
    if not line.startswith(HTTP_VERSIONS):
        return False
    return len(line) >= 12 and line[8:9] == b" " and line[9:12].isdigit()


def _is_smtp_command(payload: bytes) -> bool:
    line, complete = _first_line(payload)
    if not complete and b"\n" in payload:
        return False
    token, _, rest = line.upper().partition(b" ")
    if token not in SMTP_COMMANDS:
        return False
    if token == b"MAIL":
        return rest.startswith(b"FROM:")
    if token == b"RCPT":
        return rest.startswith(b"TO:")
    return True


def _is_smtp_response(payload: bytes, hint: AppProtocol | None) -> bool:
    line, complete = _first_line(payload)
    if len(line) < 4 or line[0:1] not in b"2345":
        return False
    if not line[1:3].isdigit() or line[3:4] not in (b" ", b"-"):
        return False
    if hint == "SMTP":
        return True
    return complete and all(0x20 <= byte < 0x7F for byte in line[4:])


def _is_dns_udp(payload: bytes) -> bool:
    if len(payload) < DNS_HEADER_LEN:
        return False
    flags = int.from_bytes(payload[2:4], "big")
    if ((flags >> 11) & 0xF) > DNS_MAX_OPCODE:
        return False
    # Only bit 6 is Z. Bits 5 and 4 are AD and CD (RFC 4035), and dig sets AD by default.
    if (flags >> 6) & 1:
        return False
    if not 1 <= int.from_bytes(payload[4:6], "big") <= DNS_MAX_QUESTION_COUNT:
        return False
    for start in (6, 8, 10):
        if int.from_bytes(payload[start : start + 2], "big") > DNS_MAX_RECORD_COUNT:
            return False
    try:
        _, offset = read_name(payload, DNS_HEADER_LEN)
    except ValueError:
        return False
    if offset + 4 > len(payload):
        return False
    qtype = int.from_bytes(payload[offset : offset + 2], "big")
    qclass = int.from_bytes(payload[offset + 2 : offset + 4], "big")
    return qtype != 0 and qclass != 0


def _is_dns_tcp(payload: bytes) -> bool:
    if len(payload) < 2:
        return False
    if int.from_bytes(payload[:2], "big") != len(payload) - 2:
        return False
    return _is_dns_udp(payload[2:])
