"""Tests for the command line and the capture loop."""

import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run
from ids.config import Config


def test_pcap_run_uses_documented_defaults() -> None:
    """A bare PCAP run keeps every default from R0.6."""
    config = parse_args(["--pcap", "capture.pcap"])

    assert config.pcap == "capture.pcap"
    assert config.interface is None
    assert config.output == "events.jsonl"
    assert config.unknown == "keep"
    assert config.count is None


def test_interface_run_records_every_option() -> None:
    """Each option reaches the configuration unchanged."""
    config = parse_args(["--interface", "en0", "--count", "10", "--unknown", "drop"])

    assert config.interface == "en0"
    assert config.pcap is None
    assert config.count == 10
    assert config.unknown == "drop"


def test_count_below_one_is_rejected() -> None:
    """A zero count must fail, because Scapy reads it as unlimited."""
    with pytest.raises(SystemExit):
        parse_args(["--pcap", "capture.pcap", "--count", "0"])


def test_run_writes_one_event_per_packet(tmp_path: Path, basic_pcap: Path) -> None:
    output = tmp_path / "events.jsonl"
    config = Config(
        interface=None,
        pcap=str(basic_pcap),
        output=str(output),
        unknown="keep",
        count=None,
    )

    assert run(config) == 0

    lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [line["packet_id"] for line in lines] == [1, 2, 3]
    assert [line["source"] for line in lines] == [f"pcap:{basic_pcap}"] * 3
