from pathlib import Path

import pytest
from scapy.all import Ether, IP, UDP, PcapReader, wrpcap

from ids.config import Config
from ids.pipeline import Pipeline


def _config() -> Config:
    return Config(
        interface=None,
        pcap="basic.pcap",
        output="events.jsonl",
        unknown="keep",
        count=None,
    )


def _pipeline() -> Pipeline:
    return Pipeline(_config(), "pcap:basic.pcap")


def test_packet_fills_the_event_envelope() -> None:
    packet = Ether() / IP() / UDP()
    packet.time = 1758441600.5

    event = _pipeline().process(packet)

    assert event is not None
    assert event.packet_id == 1
    assert event.timestamp == 1758441600.5
    assert event.timestamp_iso.startswith("2025-09-21T08:00:00")
    assert event.source == "pcap:basic.pcap"
    assert event.length == len(packet)
    assert event.link_type == "Ethernet"
    assert event.app_protocol == "UNKNOWN"
    assert event.status == "unsupported"
    assert event.errors == []


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
