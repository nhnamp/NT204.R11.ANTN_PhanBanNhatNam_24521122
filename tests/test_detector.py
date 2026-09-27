import random

import pytest

from ids.events import Detection, TransportInfo
from ids.parsers.detector import detect_app_protocol

QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"
DNS_QUERY = bytes.fromhex("123401000001000000000000") + QUESTION
DNS_QUERY_TCP = len(DNS_QUERY).to_bytes(2, "big") + DNS_QUERY


def _transport(protocol: str = "TCP", src_port: int = 40000, dst_port: int = 40000) -> TransportInfo:
    return TransportInfo(protocol=protocol, src_port=src_port, dst_port=dst_port, payload_len=0)


def _detect(payload: bytes, protocol: str = "TCP", src_port: int = 40000, dst_port: int = 40000) -> Detection:
    return detect_app_protocol(_transport(protocol, src_port, dst_port), payload)


def _dns_header(flags: int = 0x0100, question: int = 1, answer: int = 0, authority: int = 0, additional: int = 0) -> bytes:
    return b"\x12\x34" + b"".join(
        value.to_bytes(2, "big") for value in (flags, question, answer, authority, additional)
    )


@pytest.mark.parametrize(
    ("payload", "protocol", "expected"),
    [
        (b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", "TCP", ("HTTP", "http_request")),
        (b"POST /submit HTTP/1.", "TCP", ("HTTP", "http_request")),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "TCP", ("HTTP", "http_response")),
        (b"EHLO example.com\r\n", "TCP", ("SMTP", "smtp_command")),
        (b"MAIL FROM:<a@b.c>\r\n", "TCP", ("SMTP", "smtp_command")),
        (b"250 OK\r\n", "TCP", ("SMTP", "smtp_response")),
        (DNS_QUERY, "UDP", ("DNS", "dns_udp")),
        (_dns_header(flags=0x0130) + QUESTION, "UDP", ("DNS", "dns_udp")),
        (DNS_QUERY_TCP, "TCP", ("DNS", "dns_tcp")),
    ],
)
def test_a_payload_rule_matches_its_protocol(
    payload: bytes, protocol: str, expected: tuple[str, str]
) -> None:
    result = _detect(payload, protocol)

    assert (result.protocol, result.rule) == expected
    assert result.method == "payload"
    assert result.confidence == "high"


@pytest.mark.parametrize(
    ("payload", "protocol"),
    [
        (b"GET /index.html", "TCP"),
        (b"HTTP/1.1 20 OK\r\n", "TCP"),
        (b"HTTP/1.1X200 OK\r\n", "TCP"),
        (b"HELLO example.com\r\n", "TCP"),
        (b"MAIL a@b.c\r\n", "TCP"),
        (b"600 OK\r\n", "TCP"),
        (bytes.fromhex("123401000000000000000000"), "UDP"),
        ((30).to_bytes(2, "big") + DNS_QUERY, "TCP"),
    ],
)
def test_a_failed_rule_leaves_the_protocol_unknown(payload: bytes, protocol: str) -> None:
    result = _detect(payload, protocol)

    assert (result.protocol, result.method, result.rule) == ("UNKNOWN", "none", "")


@pytest.mark.parametrize(
    "payload",
    [
        _dns_header(flags=0x0100 | (3 << 11)) + QUESTION,
        _dns_header(flags=0x0100 | 0x40) + QUESTION,
        _dns_header(question=17) + QUESTION,
        _dns_header(answer=65) + QUESTION,
        _dns_header() + b"\x07exam",
        _dns_header() + b"\x00\x00\x00\x00\x01",
    ],
)
def test_a_broken_dns_header_is_not_dns(payload: bytes) -> None:
    assert _detect(payload, "UDP").protocol != "DNS"


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (80, "HTTP"),
        (8080, "HTTP"),
        (8000, "HTTP"),
        (8888, "HTTP"),
        (53, "DNS"),
        (5353, "DNS"),
        (25, "SMTP"),
        (587, "SMTP"),
        (2525, "SMTP"),
    ],
)
def test_an_empty_payload_uses_the_port_hint(port: int, expected: str) -> None:
    result = _detect(b"", dst_port=port)

    assert result == Detection(protocol=expected, method="port", confidence="low", rule="port_hint")


def test_the_source_port_is_also_a_hint() -> None:
    assert _detect(b"", src_port=80).protocol == "HTTP"


def test_an_empty_payload_without_a_hint_is_unknown() -> None:
    assert _detect(b"") == Detection(protocol="UNKNOWN", method="none", confidence="low", rule="")


def test_a_packet_without_a_transport_is_unknown() -> None:
    assert detect_app_protocol(None, b"").protocol == "UNKNOWN"


def test_a_matching_port_raises_the_method() -> None:
    result = _detect(b"GET / HTTP/1.1\r\n\r\n", dst_port=80)

    assert result == Detection(
        protocol="HTTP", method="port+payload", confidence="high", rule="http_request"
    )


@pytest.mark.parametrize(("port", "protocol"), [(4444, "TCP"), (53, "UDP"), (80, "TCP"), (25, "TCP")])
def test_a_known_port_does_not_confirm_random_bytes(port: int, protocol: str) -> None:
    payload = random.Random(port).randbytes(64)

    result = _detect(payload, protocol, dst_port=port)

    assert (result.protocol, result.method) == ("UNKNOWN", "none")


def test_detection_never_raises() -> None:
    rng = random.Random(0)
    results = []
    for _ in range(10_000):
        payload = rng.randbytes(rng.randrange(0, 200))
        transport = _transport("TCP" if rng.random() < 0.5 else "UDP")
        results.append(detect_app_protocol(transport, payload))

    assert {result.protocol for result in results} <= {"HTTP", "DNS", "SMTP", "UNKNOWN"}
