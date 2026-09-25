"""Tests for the PCAP capture source."""

from collections.abc import Callable
from pathlib import Path

import pytest

from ids.capture.pcap import PcapSource


def test_packets_carry_the_file_timestamps(basic_pcap: Path) -> None:
    packets = list(PcapSource(basic_pcap))

    assert [type(packet).__name__ for packet in packets] == ["Ether", "Ether", "Ether"]
    assert [float(packet.time) for packet in packets] == [
        1758441600.0,
        1758441600.5,
        1758441601.0,
    ]


def test_describe_names_the_capture_file() -> None:
    assert PcapSource("captures/basic.pcap").describe() == "pcap:captures/basic.pcap"


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        pytest.param(lambda data: data[:-8], 3, id="truncated last record"),
        pytest.param(lambda data: b"not a capture file", 0, id="not a pcap"),
    ],
)
def test_a_damaged_capture_stops_without_an_exception(
    basic_pcap: Path, tmp_path: Path, damage: Callable[[bytes], bytes], expected: int
) -> None:
    """Scapy returns a cut last record as a short packet, and rejects a foreign file (R2.3)."""
    damaged = tmp_path / "damaged.pcap"
    damaged.write_bytes(damage(basic_pcap.read_bytes()))

    assert len(list(PcapSource(damaged))) == expected
