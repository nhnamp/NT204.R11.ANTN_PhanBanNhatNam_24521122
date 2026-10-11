"""Tests for the events file source."""

from pathlib import Path

import pytest

from ids.capture.events import EventFileSource
from ids.output import encode_line

GOOD = b'{"n": 2}\n'


def _read(tmp_path: Path, data: bytes, **options: int) -> list[tuple[dict, list[dict]]]:
    path = tmp_path / "events.jsonl"
    path.write_bytes(data)
    return list(EventFileSource(path, **options))


def _line_of(size: int) -> bytes:
    """Build a JSON object line of exactly `size` bytes, without the line end."""
    return b'{"a":"' + b"x" * (size - 8) + b'"}'


@pytest.mark.parametrize(
    ("bad_line", "reason"),
    [
        (b"{not json", "not valid JSON"),
        (b"[1, 2]", "not an object"),
        (b'"text"', "not an object"),
        (b'{"timestamp": NaN}', "NaN is not allowed"),
        (b'{"count": Infinity}', "Infinity is not allowed"),
        (b'{"count": 1e999}', "cannot be written as JSON"),
        (b'{"text": "\\ud800"}', "cannot be written as JSON"),
        (b'{"text": "\xff\xfe"}', "not valid UTF-8"),
        (b'{"big": ' + b"9" * 4301 + b"}", "not valid JSON"),
        (b"[" * 100_000 + b"]" * 100_000, "nested too deeply"),
        (b"\xef\xbb\xbf{}", "not valid JSON"),
    ],
    ids=["not-json", "list", "string", "nan", "infinity", "huge-float", "lone-surrogate", "not-utf8", "huge-int", "deep-nesting", "bom-after-line-1"],
)
def test_bad_line_becomes_a_marked_record_and_the_next_line_still_reads(
    tmp_path: Path, bad_line: bytes, reason: str
) -> None:
    # The bom-after-line-1 case needs a line before it, so every case starts at line 2.
    items = _read(tmp_path, GOOD + bad_line + b"\n" + GOOD)

    assert items[0] == ({"n": 2}, [])
    record, errors = items[1]
    assert record == {"source": f"events:{tmp_path / 'events.jsonl'}:2"}
    assert [(e["stage"], e["type"]) for e in errors] == [("input", "invalid_record")]
    assert reason in errors[0]["message"]
    encode_line(record)
    encode_line({"processing_errors": errors})
    assert items[2] == ({"n": 2}, [])


@pytest.mark.parametrize(
    ("size", "line_end", "accepted"),
    [
        (20, b"\n", True),
        (20, b"\r\n", True),
        (21, b"\n", False),
        (21, b"\r\n", False),
        (500, b"\n", False),
    ],
)
def test_line_limit_boundary(tmp_path: Path, size: int, line_end: bytes, accepted: bool) -> None:
    items = _read(tmp_path, _line_of(size) + line_end + GOOD, max_line_bytes=20)

    assert (items[0][1] == []) is accepted
    assert items[-1] == ({"n": 2}, [])


@pytest.mark.parametrize(("size", "accepted"), [(20, True), (21, False), (500, False)])
def test_line_limit_boundary_on_a_last_line_with_no_line_end(
    tmp_path: Path, size: int, accepted: bool
) -> None:
    items = _read(tmp_path, _line_of(size), max_line_bytes=20)

    assert len(items) == 1
    assert (items[0][1] == []) is accepted


def test_line_numbers_count_empty_and_over_long_lines(tmp_path: Path) -> None:
    data = b"\n" + _line_of(500) + b"\n" + b"{bad\n"

    items = _read(tmp_path, data, max_line_bytes=20)

    assert [record["source"].rsplit(":", 1)[1] for record, _ in items] == ["2", "3"]


def test_byte_order_mark_on_the_first_line_is_accepted(tmp_path: Path) -> None:
    items = _read(tmp_path, b"\xef\xbb\xbf" + GOOD)

    assert items == [({"n": 2}, [])]


def test_byte_order_mark_before_an_empty_line_is_skipped(tmp_path: Path) -> None:
    items = _read(tmp_path, b"\xef\xbb\xbf\n" + GOOD)

    assert items == [({"n": 2}, [])]


def test_empty_file_gives_no_records(tmp_path: Path) -> None:
    assert _read(tmp_path, b"") == []


def test_missing_file_raises_os_error(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        list(EventFileSource(tmp_path / "missing.jsonl"))
