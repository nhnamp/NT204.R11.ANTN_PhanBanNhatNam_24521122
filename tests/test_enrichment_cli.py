"""Tests for the capture loop with the enricher: the three sources, the guards, and the summary."""

import json
from pathlib import Path

import pytest
from scapy.all import Ether

from ids.cli import _write_record, parse_args, run
from ids.contract import ENRICHMENT_FIELDS
from ids.enrich import Enricher
from ids.events import Event
from ids.output import JsonLinesWriter


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _run(*args: str) -> int:
    return run(parse_args(list(args)))


def _base(record: dict) -> dict:
    return {key: value for key, value in record.items() if key not in ENRICHMENT_FIELDS}


def test_a_pcap_run_gives_every_line_every_enrichment_field(tmp_path: Path, basic_pcap: Path) -> None:
    flows = tmp_path / "flows.jsonl"

    assert _run("--pcap", str(basic_pcap), "--output", str(tmp_path / "out.jsonl"), "--flows-output", str(flows)) == 0

    lines = _lines(tmp_path / "out.jsonl")
    assert len(lines) == 3
    assert all(set(ENRICHMENT_FIELDS) <= set(line) for line in lines)
    _lines(flows)


def test_an_events_run_replays_an_output_file_without_changing_the_base_fields(
    tmp_path: Path, basic_pcap: Path
) -> None:
    first, second = tmp_path / "first.jsonl", tmp_path / "second.jsonl"
    assert _run("--pcap", str(basic_pcap), "--output", str(first)) == 0

    assert _run("--events", str(first), "--output", str(second)) == 0

    replayed = _lines(second)
    assert [_base(line) for line in replayed] == [_base(line) for line in _lines(first)]
    assert all(set(ENRICHMENT_FIELDS) <= set(line) for line in replayed)


def test_a_bad_events_file_gives_one_marked_line_per_bad_line_and_exit_zero(tmp_path: Path) -> None:
    bad_lines = [
        b'{"timestamp": NaN}',
        b'{"text": "\\ud800"}',
        b'{"big": ' + b"9" * 4301 + b"}",
        b'{"a": "' + b"x" * 2_000_000 + b'"}',
        b"[" * 100_000,
    ]
    source = tmp_path / "bad.jsonl"
    source.write_bytes(b"\n".join(bad_lines) + b'\n{"n": 1}\n')

    assert _run("--events", str(source), "--output", str(tmp_path / "out.jsonl")) == 0

    lines = _lines(tmp_path / "out.jsonl")
    assert len(lines) == 6
    for line in lines[:5]:
        assert [error["type"] for error in line["processing_errors"]] == ["invalid_record"]
    assert lines[5]["n"] == 1 and lines[5]["processing_errors"] == []


def test_a_status_that_is_not_a_known_word_goes_to_other(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    records = [{"timestamp": 1}, {"status": ["ok"]}, {"status": {}}, {"status": "weird"}, {"status": "ok"}]
    source = tmp_path / "records.jsonl"
    source.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    assert _run("--events", str(source), "--output", str(tmp_path / "out.jsonl")) == 0

    summary = capsys.readouterr().err.splitlines()
    assert "ok: 1" in summary
    assert "other: 4" in summary
    assert "events written: 5" in summary


class _BadRecordEnricher(Enricher):
    """Produce a record whose enrichment holds a value that JSON cannot carry."""

    def process(self, record: dict, input_errors: list[dict] | None = None):
        output, exported = super().process(record, input_errors)
        output["decoded"] = [float("nan")]
        return output, exported


def test_a_record_that_cannot_be_written_keeps_its_base_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, basic_pcap: Path
) -> None:
    monkeypatch.setattr("ids.cli.Enricher", _BadRecordEnricher)

    assert _run("--pcap", str(basic_pcap), "--output", str(tmp_path / "out.jsonl")) == 0

    lines = _lines(tmp_path / "out.jsonl")
    assert [line["packet_id"] for line in lines] == [1, 2, 3]
    assert lines[0]["decoded"] == []
    assert lines[0]["reason"] == "record could not be written"
    assert [(e["stage"], e["type"]) for e in lines[0]["processing_errors"]] == [("output", "ValueError")]


def test_the_last_fallback_writes_a_line_even_when_the_source_has_a_lone_surrogate(tmp_path: Path) -> None:
    path = tmp_path / "out.jsonl"
    record = {"source": "events:\udcff", "decoded": [float("nan")]}

    with JsonLinesWriter(path) as writer:
        written = _write_record(writer, record)

    (line,) = _lines(path)
    assert written is not None
    assert line["source"] == "events:?"
    assert line["processing_errors"][0]["stage"] == "output"


def test_an_event_that_cannot_become_a_record_still_gives_a_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, basic_pcap: Path
) -> None:
    def broken(self: Event) -> dict:
        raise TypeError("not JSON")

    monkeypatch.setattr(Event, "to_dict", broken)

    assert _run("--pcap", str(basic_pcap), "--count", "1", "--output", str(tmp_path / "out.jsonl")) == 0

    (line,) = _lines(tmp_path / "out.jsonl")
    assert [(e["stage"], e["type"]) for e in line["processing_errors"]] == [("input", "TypeError")]


class _FlowEnricher(Enricher):
    """Export two flows for every record and one more at the end, and one of them is not writable."""

    def process(self, record: dict, input_errors: list[dict] | None = None):
        output, _ = super().process(record, input_errors)
        return output, [{"flow_id": "good"}, {"flow_id": float("nan")}]

    def flush(self) -> list[dict]:
        return [{"flow_id": "last"}]


def test_a_flow_that_cannot_be_written_is_reported_and_the_run_goes_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, basic_pcap: Path, capsys: pytest.CaptureFixture
) -> None:
    monkeypatch.setattr("ids.cli.Enricher", _FlowEnricher)
    flows = tmp_path / "flows.jsonl"

    assert _run("--pcap", str(basic_pcap), "--output", str(tmp_path / "out.jsonl"), "--flows-output", str(flows)) == 0

    assert [line["flow_id"] for line in _lines(flows)] == ["good", "good", "good", "last"]
    error = capsys.readouterr().err
    assert error.count("warning: a flow record could not be written") == 3
    assert "flows written: 4" in error.splitlines()


class _InterruptedSource:
    def describe(self) -> str:
        return "live:lo0"

    def __iter__(self):
        yield Ether()
        raise KeyboardInterrupt


@pytest.mark.parametrize("stop", ["interrupt", "count"])
def test_the_remaining_flows_are_written_when_the_run_stops_early(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, basic_pcap: Path, stop: str
) -> None:
    monkeypatch.setattr("ids.cli.Enricher", _FlowEnricher)
    flows = tmp_path / "flows.jsonl"
    if stop == "interrupt":
        monkeypatch.setattr("ids.cli._build_source", lambda config: _InterruptedSource())
        args = ["--interface", "lo0"]
    else:
        args = ["--pcap", str(basic_pcap), "--count", "1"]

    assert _run(*args, "--output", str(tmp_path / "out.jsonl"), "--flows-output", str(flows)) == 0

    assert _lines(flows)[-1] == {"flow_id": "last"}


def test_a_failing_flush_does_not_hide_the_interrupt_or_change_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    class Broken(Enricher):
        def flush(self) -> list[dict]:
            raise RuntimeError("tracker bug")

    monkeypatch.setattr("ids.cli.Enricher", Broken)
    monkeypatch.setattr("ids.cli._build_source", lambda config: _InterruptedSource())

    assert _run("--interface", "lo0", "--output", str(tmp_path / "out.jsonl")) == 0

    error = capsys.readouterr().err
    assert "interrupted" in error
    assert "the remaining flows were not exported (tracker bug)" in error


@pytest.mark.parametrize(
    "args",
    [
        ["--pcap", "in.pcap", "--output", "x.jsonl", "--flows-output", "./x.jsonl"],
        ["--pcap", "in.pcap", "--output", "in.pcap"],
        ["--events", "in.jsonl", "--flows-output", "in.jsonl"],
        ["--events", "in.jsonl", "--pcap", "in.pcap"],
    ],
)
def test_conflicting_paths_are_a_usage_error(args: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        parse_args(args)

    assert info.value.code == 2


def test_a_missing_events_file_exits_with_one_error_line(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    assert _run("--events", str(tmp_path / "missing.jsonl"), "--output", str(tmp_path / "out.jsonl")) == 1

    assert capsys.readouterr().err.startswith("error:")
