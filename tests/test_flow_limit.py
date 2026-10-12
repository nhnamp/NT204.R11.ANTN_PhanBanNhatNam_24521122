"""Tests for the flow limit: which flow leaves when the table is full."""

import pytest

from ids.stages.flow import FlowTracker
from tests.test_flow_expiry import _exported, _packet


def test_the_third_flow_evicts_the_oldest_flow_of_two() -> None:
    tracker = FlowTracker(max_flows=2)

    assert _exported(tracker, _packet(1, 1.0), _packet(2, 2.0)) == []
    (evicted,) = _exported(tracker, _packet(3, 3.0))

    assert (evicted["end_reason"], evicted["last_seen"], evicted["packet_count"]) == ("evicted", 1.0, 1)
    assert [flow["last_seen"] for flow in tracker.flush()] == [2.0, 3.0]


def test_a_packet_of_a_known_flow_evicts_nothing_at_the_limit() -> None:
    tracker = FlowTracker(max_flows=2)

    exported = _exported(tracker, _packet(1, 1.0), _packet(2, 2.0), _packet(1, 3.0), _packet(2, 4.0))

    assert exported == []


@pytest.mark.parametrize(
    ("first", "second", "evicted"),
    [
        (("UDP", 1.0), ("TCP", 2.0), "UDP"),
        (("TCP", 1.0), ("UDP", 2.0), "TCP"),
        (("UDP", 5.0), ("TCP", 5.0), "UDP"),
        (("TCP", 5.0), ("UDP", 5.0), "TCP"),
    ],
)
def test_the_oldest_flow_of_both_tables_is_evicted_and_a_tie_goes_to_the_older_flow(
    first: tuple[str, float], second: tuple[str, float], evicted: str
) -> None:
    tracker = FlowTracker(max_flows=2)

    (exported,) = _exported(
        tracker, _packet(1, first[1], first[0]), _packet(2, second[1], second[0]), _packet(3, 6.0, "UDP")
    )

    assert exported["protocol"] == evicted
