from pathlib import Path
from typing import Literal

import pytest
from scapy.all import ARP, ICMP, Ether, IP, Raw, TCP, UDP, PcapReader, wrpcap
from scapy.packet import Packet

from ids.config import Config
from ids.events import HttpInfo
from ids.pipeline import Pipeline


def _config(unknown: Literal["keep", "drop"] = "keep") -> Config:
    return Config(
        interface=None,
        pcap="basic.pcap",
        output="events.jsonl",
        unknown=unknown,
        count=None,
    )


def _pipeline(unknown: Literal["keep", "drop"] = "keep") -> Pipeline:
    return Pipeline(_config(unknown), "pcap:basic.pcap")


def test_packet_fills_the_event_envelope() -> None:
    crafted = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / UDP()
    packet = Ether(bytes(crafted))
    packet.time = 1758441600.5

    event = _pipeline().process(packet)

    assert event is not None
    assert event.packet_id == 1
    assert event.timestamp == 1758441600.5
    assert event.timestamp_iso.startswith("2025-09-21T08:00:00")
    assert event.source == "pcap:basic.pcap"
    assert event.length == len(packet)
    assert event.link_type == "Ethernet"
    assert event.network is not None
    assert event.transport is not None
    assert event.transport.protocol == "UDP"
    assert event.app_protocol == "DNS"
    assert event.detection is not None
    assert event.detection.method == "port"
    assert event.status == "ok"
    assert event.errors == []


def test_non_first_fragment_is_partial() -> None:
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", flags="MF", frag=185, proto=6)
        / Raw(b"x" * 20)
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert event.network is not None
    assert event.network.frag_offset == 1480
    assert event.transport is None
    assert event.status == "partial"
    assert [(error.stage, error.type) for error in event.errors] == [("network", "fragment")]


def test_non_ipv4_is_kept_as_unknown_by_default() -> None:
    packet = Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP()

    event = _pipeline().process(packet)

    assert event is not None
    assert event.network is None
    assert event.app_protocol == "UNKNOWN"
    assert event.status == "unsupported"


@pytest.mark.parametrize(
    "packet",
    [
        pytest.param(Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / ARP(), id="ARP"),
        pytest.param(
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP() / ICMP(), id="ICMP"
        ),
    ],
)
def test_unsupported_packet_is_dropped_on_request(packet: Packet) -> None:
    assert _pipeline("drop").process(Ether(bytes(packet))) is None


def test_tcp_payload_reaches_the_event() -> None:
    body = b"hello"
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(body)
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert event.transport is not None
    assert event.transport.payload_len == len(body)
    assert event.payload_len == len(body)
    assert event.payload_preview == body.hex()
    assert event.status == "ok"


def test_http_payload_becomes_the_application() -> None:
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(request)
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert isinstance(event.application, HttpInfo)
    assert (event.application.kind, event.application.host) == ("request", "example.com")
    assert event.status == "ok"


def test_a_port_only_detection_skips_the_application_parser() -> None:
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="S")
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert event.detection is not None
    assert event.detection.method == "port"
    assert event.application is None


def test_a_partial_http_message_is_partial() -> None:
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com")
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert isinstance(event.application, HttpInfo)
    assert event.application.partial is True
    assert event.status == "partial"


def test_an_http_limit_is_partial() -> None:
    request = b"GET / HTTP/1.1\r\n" + b"".join(b"X-%d: v\r\n" % index for index in range(200))
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA")
        / Raw(request)
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert event.status == "partial"
    assert [(error.stage, error.type) for error in event.errors] == [("http", "limit")]


QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"
ANSWER_OFFSET = 12 + len(QUESTION)
LONG_NAME = b"".join(bytes([63]) + b"a" * 63 for _ in range(4)) + b"\x00"


@pytest.mark.parametrize(
    "answer_name",
    [
        b"\x01a\xc0" + bytes([ANSWER_OFFSET]),
        b"\xc0\x20",
        LONG_NAME,
        b"\x40" + b"a" * 64,
    ],
)
def test_a_malformed_dns_answer_keeps_the_lower_layers(answer_name: bytes) -> None:
    dns = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + QUESTION + answer_name
    crafted = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=53)
        / Raw(dns)
    )

    event = _pipeline().process(Ether(bytes(crafted)))

    assert event is not None
    assert event.status == "malformed"
    assert event.network is not None
    assert event.transport is not None
    assert [(error.stage, error.type) for error in event.errors] == [("dns", "malformed")]


def test_packet_ids_increment_from_one() -> None:
    pipeline = _pipeline()

    assert [pipeline.process(Ether()).packet_id for _ in range(3)] == [1, 2, 3]


@pytest.mark.parametrize("packet", [None, object(), "not a packet", 42])
def test_any_object_becomes_a_malformed_event(packet: object) -> None:
    event = _pipeline().process(packet)

    assert event is not None
    assert event.status == "malformed"
    assert len(event.errors) == 1
    assert event.errors[0].stage == "pipeline"


def test_pcap_timestamp_becomes_a_json_float(tmp_path: Path) -> None:
    """PcapReader gives packet.time as EDecimal, which to_dict() rejects."""
    path = tmp_path / "one.pcap"
    packet = Ether() / IP() / UDP()
    packet.time = 1758441600.5
    wrpcap(str(path), [packet])

    with PcapReader(str(path)) as reader:
        event = _pipeline().process(next(iter(reader)))

    assert event is not None
    assert type(event.timestamp) is float
    assert event.to_dict()["timestamp"] == 1758441600.5
