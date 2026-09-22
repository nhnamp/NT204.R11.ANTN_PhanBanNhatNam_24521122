"""Tests for the mapping from command-line arguments to a run configuration."""

import pytest

from ids.cli import parse_args


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
