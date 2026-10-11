"""Tests that run the normalization fixtures through the pipeline, the enricher, and the CLI."""

import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run
from ids.contract import empty_normalized
from tests.test_decoding_fixtures import FIXTURE_DIR, _enrich

EVENTS_DIR = FIXTURE_DIR / "events"


def _run_events(name: str, tmp_path: Path, *options: str) -> list[dict]:
    output = tmp_path / "out.jsonl"
    assert run(parse_args(["--events", str(EVENTS_DIR / name), "--output", str(output), *options])) == 0
    return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]


def test_http_requests_in_different_case_and_format_give_the_same_view() -> None:
    first, second, _ = (record["normalized"] for record in _enrich("normalization.pcap"))

    for normalized in (first, second):
        assert (normalized["host"], normalized["path"], normalized["query"]) == ("example.com", "/b", "q=1")
        assert normalized["headers"]["x-test"] == ["a", "b"]


def test_dns_names_in_capitals_are_lower_case() -> None:
    assert _enrich("normalization.pcap")[2]["normalized"]["domains"] == ["www.example.com"]


def test_packet_records_keep_the_timestamp_of_the_base_event() -> None:
    for record in _enrich("normalization.pcap"):
        assert record["normalized"]["timestamp"] == record["timestamp"]
        assert record["normalized"]["timestamp_iso"] == record["timestamp_iso"]


def test_events_in_different_case_and_format_give_the_same_view(tmp_path: Path) -> None:
    records = _run_events("protocol_and_ip.jsonl", tmp_path)

    assert records[0]["normalized"] == records[1]["normalized"]
    assert records[0]["normalized"]["src_ip"] == "2001:db8::1"
    assert [(r["preprocess_status"], r["processing_action"]) for r in records] == [
        ("valid", "keep"), ("valid", "keep"), ("partial", "skip_flow"),
    ]
    assert records[2]["reason"] == "address is missing or invalid"


def test_events_without_optional_fields_give_null_and_empty_values(tmp_path: Path) -> None:
    records = _run_events("missing_fields.jsonl", tmp_path)

    assert [(r["preprocess_status"], r["decode_status"], r["processing_errors"]) for r in records] == [
        ("valid", "not_applicable", []), ("partial", "not_applicable", []),
    ]
    assert records[0]["normalized"]["host"] is None
    assert records[0]["normalized"]["headers"] == {}
    assert records[0]["normalized"]["length"] is None
    assert records[1]["normalized"] == {**empty_normalized(), "timestamp": 1758441600.0, "timestamp_iso": "2025-09-21T08:00:00+00:00"}


KEPT_REASONS = [
    ("invalid", "timestamp is missing or unusable"),
    ("invalid", "input line is not a usable event"),
    ("invalid", "input line is not a usable event"),
    ("invalid", "input line is not a usable event"),
    ("partial", "port is missing or out of range"),
    ("invalid", "timestamp is missing or unusable"),
    ("invalid", "timestamp is missing or unusable"),
    ("partial", "no network layer; no transport layer"),
]


@pytest.mark.parametrize(
    ("options", "expected", "dropped"),
    [
        ((), KEPT_REASONS, 0),
        (("--unknown", "drop"), [KEPT_REASONS[4]], 7),
    ],
    ids=["keep", "drop"],
)
def test_invalid_and_unsupported_events_are_marked_or_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture, options: tuple, expected: list[tuple], dropped: int
) -> None:
    records = _run_events("invalid_events.jsonl", tmp_path, *options)

    assert [(record["preprocess_status"], record["reason"]) for record in records] == expected
    assert f"dropped: {dropped}" in capsys.readouterr().err.splitlines()
    assert all(record["processing_action"] == "skip_flow" for record in records)
