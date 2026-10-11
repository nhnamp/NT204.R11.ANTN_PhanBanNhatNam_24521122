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


def test_event_and_its_dict_give_the_same_line(tmp_path: Path) -> None:
    event = _event(1)
    from_event = tmp_path / "event.jsonl"
    from_dict = tmp_path / "dict.jsonl"
    with JsonLinesWriter(from_event) as writer:
        writer.write(event)
    with JsonLinesWriter(from_dict) as writer:
        writer.write(event.to_dict())

    assert from_event.read_bytes() == from_dict.read_bytes()


def _nested_dict(depth: int) -> dict:
    record: object = 1
    for _ in range(depth):
        record = {"a": record}
    return {"nested": record}


BAD_RECORDS = {
    "nan": {"timestamp": float("nan")},
    "lone surrogate": {"text": "\ud800"},
    "bytes": {"payload": b"x"},
}


@pytest.mark.parametrize("record", BAD_RECORDS.values(), ids=BAD_RECORDS.keys())
def test_bad_record_raises_and_adds_nothing_to_the_file(tmp_path: Path, record: dict) -> None:
    """The failed record must not reach the file, and must not count toward the flush."""
    path = tmp_path / "records.jsonl"
    with JsonLinesWriter(path, flush_every=3) as writer:
        writer.write({"n": 1})
        with pytest.raises(ValueError):
            writer.write(record)
        writer.write({"n": 2})
        assert path.read_text(encoding="utf-8") == ""

        writer.write({"n": 3})
        assert path.read_text(encoding="utf-8").splitlines() == ['{"n": 1}', '{"n": 2}', '{"n": 3}']


def _raise_recursion_error(*args: object, **kwargs: object) -> str:
    raise RecursionError("maximum recursion depth exceeded")


def test_a_recursion_error_while_serializing_becomes_a_value_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """json.dumps raises RecursionError only when the C stack is small enough, so force it."""
    monkeypatch.setattr("ids.output.json.dumps", _raise_recursion_error)
    path = tmp_path / "records.jsonl"

    with JsonLinesWriter(path) as writer:
        with pytest.raises(ValueError):
            writer.write({"n": 1})

    assert path.read_text(encoding="utf-8") == ""


def test_a_very_deep_record_is_either_written_whole_or_refused(tmp_path: Path) -> None:
    """The depth that fails depends on the machine, so accept both outcomes and nothing else."""
    path = tmp_path / "records.jsonl"

    with JsonLinesWriter(path) as writer:
        try:
            writer.write(_nested_dict(200_000))
        except ValueError:
            pass

    assert path.read_text(encoding="utf-8").count("\n") <= 1
