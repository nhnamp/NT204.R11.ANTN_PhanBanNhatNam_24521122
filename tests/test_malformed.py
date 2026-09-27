"""Tests that the R9.2 bad-input corpus never escapes an exception."""

from pathlib import Path

import pytest

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.events import Event
from ids.pipeline import Pipeline

MALFORMED_DIR = Path(__file__).parent / "fixtures" / "malformed"
CORPUS = sorted(MALFORMED_DIR.glob("*.pcap"))
STATUSES = {"ok", "partial", "unsupported", "malformed"}


def _events(path: Path, unknown: str = "keep") -> list[Event | None]:
    config = Config(
        interface=None, pcap=str(path), output="events.jsonl", unknown=unknown, count=None
    )
    pipeline = Pipeline(config, f"pcap:{path}")
    return [pipeline.process(packet) for packet in PcapSource(path)]


def test_the_corpus_covers_every_requirement_item() -> None:
    items = {path.name[:2] for path in MALFORMED_DIR.iterdir()}

    assert items == {f"{number:02d}" for number in range(1, 21)}


@pytest.mark.parametrize("path", CORPUS, ids=lambda path: path.name)
def test_every_corpus_packet_becomes_an_event(path: Path) -> None:
    events = _events(path)

    assert events
    assert all(event is not None for event in events)
    assert {event.status for event in events} <= STATUSES


def test_a_file_that_is_not_a_pcap_yields_nothing() -> None:
    assert _events(MALFORMED_DIR / "19_not_a_pcap.txt") == []


def test_the_drop_policy_only_removes_unsupported_events() -> None:
    for path in CORPUS:
        kept = _events(path)
        dropped = _events(path, "drop")
        assert len(kept) == len(dropped)
        for event, result in zip(kept, dropped):
            if event is not None and event.status != "unsupported":
                assert result is not None
                assert result.packet_id == event.packet_id
            else:
                assert result is None
