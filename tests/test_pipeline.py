from pathlib import Path
from typing import Literal

import pytest
from scapy.all import ARP, ICMP, Ether, IP, Raw, TCP, UDP, PcapReader, wrpcap
from scapy.packet import Packet

from ids.config import Config
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
    assert event.app_protocol == "UNKNOWN"
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
