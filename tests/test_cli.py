"""Tests for the command line and the capture loop."""

import json
from pathlib import Path

import pytest
from scapy.all import Ether

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


def test_enrichment_options_have_documented_defaults() -> None:
    config = parse_args(["--pcap", "capture.pcap"])

    assert config.payload == "full"
    assert config.payload_limit == 4096
    assert config.tcp_timeout == 120.0
    assert config.udp_timeout == 30.0
    assert config.max_flows == 100_000
    assert config.flows_output == "flows.jsonl"


def test_enrichment_options_reach_the_configuration() -> None:
    config = parse_args(
        [
            "--pcap", "capture.pcap",
            "--payload", "preview",
            "--payload-limit", "512",
            "--tcp-timeout", "5.5",
            "--udp-timeout", "2",
            "--max-flows", "10",
            "--flows-output", "flows.out",
        ]
    )

    assert config.payload == "preview"
    assert config.payload_limit == 512
    assert config.tcp_timeout == 5.5
    assert config.udp_timeout == 2.0
    assert config.max_flows == 10
    assert config.flows_output == "flows.out"


@pytest.mark.parametrize(
    "option",
    [
        "--payload-limit=0",
        "--payload-limit=1.5",
        "--max-flows=0",
        "--tcp-timeout=0",
        "--udp-timeout=-1",
        "--tcp-timeout=nan",
        "--udp-timeout=inf",
    ],
)
def test_option_outside_its_range_is_a_usage_error(option: str) -> None:
    with pytest.raises(SystemExit) as info:
        parse_args(["--pcap", "capture.pcap", option])

    assert info.value.code == 2


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


def test_unknown_drop_removes_unsupported_packets_and_counts_them(
    tmp_path: Path, basic_pcap: Path, capsys: pytest.CaptureFixture
) -> None:
    output = tmp_path / "events.jsonl"
    config = Config(
        interface=None,
        pcap=str(basic_pcap),
        output=str(output),
        unknown="drop",
        count=None,
    )

    assert run(config) == 0

    lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [line["packet_id"] for line in lines] == [1, 2]
    assert "dropped: 1" in capsys.readouterr().err


def test_permission_error_exits_with_a_sudo_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    def denied(**kwargs: object) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("ids.capture.live.sniff", denied)
    config = Config(
        interface="en0",
        pcap=None,
        output=str(tmp_path / "events.jsonl"),
        unknown="keep",
        count=None,
    )

    assert run(config) == 1
    assert "sudo" in capsys.readouterr().err


def test_interrupt_closes_the_file_and_exits_zero(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Interrupted:
        def describe(self) -> str:
            return "live:lo0"

        def __iter__(self):
            yield Ether()
            raise KeyboardInterrupt

    monkeypatch.setattr("ids.cli._build_source", lambda config: Interrupted())
    output = tmp_path / "events.jsonl"
    config = Config(
        interface="lo0",
        pcap=None,
        output=str(output),
        unknown="keep",
        count=None,
    )

    assert run(config) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1


def test_the_summary_counts_every_status(
    tmp_path: Path, basic_pcap: Path, capsys: pytest.CaptureFixture
) -> None:
    output = tmp_path / "events.jsonl"
    config = Config(
        interface=None,
        pcap=str(basic_pcap),
        output=str(output),
        unknown="keep",
        count=None,
    )

    assert run(config) == 0

    summary = capsys.readouterr().err
    assert "ok: 2" in summary
    assert "unsupported: 1" in summary
    assert "partial: 0" in summary
    assert "malformed: 0" in summary
    assert "dropped: 0" in summary
