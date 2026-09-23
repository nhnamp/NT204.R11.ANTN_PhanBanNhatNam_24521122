"""Tests for the JSON Lines writer."""

import json
from pathlib import Path

import pytest

from ids.events import Event
from ids.output import JsonLinesWriter


def _event(packet_id: int) -> Event:
    """Build the smallest valid event, so a writer test stays focused."""
    return Event(
        packet_id=packet_id,
        timestamp=1758441600.0 + packet_id,
        timestamp_iso="2025-09-21T08:00:00+00:00",
        source="pcap:café.pcap",
        length=60,
        link_type="Ethernet",
        network=None,
        transport=None,
        app_protocol="UNKNOWN",
        detection=None,
        application=None,
        payload_len=0,
        payload_preview="",
        status="unsupported",
        errors=[],
    )


def test_write_emits_one_json_line_per_event(tmp_path: Path) -> None:
    """Three events must give three parseable lines, in order, unescaped."""
    path = tmp_path / "events.jsonl"
    with JsonLinesWriter(path) as writer:
        for packet_id in (1, 2, 3):
            writer.write(_event(packet_id))

    text = path.read_text(encoding="utf-8")
    assert [json.loads(line)["packet_id"] for line in text.splitlines()] == [1, 2, 3]
    assert "café" in text


def test_flush_every_writes_lines_before_close(tmp_path: Path) -> None:
    """The periodic flush must reach disk while the writer is still open."""
    path = tmp_path / "events.jsonl"
    with JsonLinesWriter(path, flush_every=2) as writer:
        writer.write(_event(1))
        writer.write(_event(2))
        assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_close_runs_when_the_body_raises(tmp_path: Path) -> None:
    """An exception inside the block must still close the file."""
    path = tmp_path / "events.jsonl"
    with pytest.raises(RuntimeError):
        with JsonLinesWriter(path) as writer:
            writer.write(_event(1))
            raise RuntimeError("interrupted")

    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
    with pytest.raises(ValueError):
        writer.write(_event(2))
