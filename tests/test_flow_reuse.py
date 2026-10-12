"""Tests for the reuse of a 5-tuple: a new connection after the old one ended."""

import pytest

from ids.stages.flow import FlowTracker
from tests.test_flow import CLIENT, KNOWN_ID, SERVER, _view

FROM_CLIENT, FROM_SERVER = True, False
HANDSHAKE = [(["SYN"], FROM_CLIENT), (["SYN", "ACK"], FROM_SERVER), (["ACK"], FROM_CLIENT)]
FIN_CLOSE = [*HANDSHAKE, (["FIN", "ACK"], FROM_CLIENT), (["FIN", "ACK"], FROM_SERVER), (["ACK"], FROM_CLIENT)]
START = 1758441600.0


def _send(tracker: FlowTracker, packets: list[tuple[list[str], bool]], at: float = START, step: float = 1.0):
    """Send the packets one `step` apart. Return the flow id of each packet and every exported flow."""
    ids, exported = [], []
    for index, (flags, from_client) in enumerate(packets):
        source, destination = (CLIENT, SERVER) if from_client else (SERVER, CLIENT)
        flow_id, _, left = tracker.update(_view(source, destination, flags=flags, timestamp=at + index * step))
        ids.append(flow_id)
        exported += left
    return ids, exported


@pytest.mark.parametrize(
    ("packets", "state"),
    [
        (FIN_CLOSE, "CLOSED"),
        ([(["SYN"], FROM_CLIENT), (["RST"], FROM_SERVER)], "RESET"),
        ([(["SYN"], FROM_CLIENT), (["FIN", "ACK"], FROM_CLIENT)], "CLOSING"),
    ],
)
def test_a_new_syn_after_the_end_of_a_connection_starts_a_new_flow(packets: list, state: str) -> None:
    tracker = FlowTracker()
    ids, _ = _send(tracker, packets)

    new_ids, exported = _send(tracker, [(["SYN"], FROM_CLIENT)], at=START + 100)

    (old,) = exported
    assert (old["flow_id"], old["end_reason"], old["state"], old["packet_count"]) == (
        ids[0], "new_connection", state, len(packets)
    )
    assert new_ids[0] != ids[0]
    assert new_ids[0] == FlowTracker().update(_view(timestamp=START + 100, flags=["SYN"]))[0]
    (new,) = tracker.flush()
    assert (new["flow_id"], new["state"], new["packet_count"], new["syn_count"]) == (new_ids[0], "HANDSHAKE", 1, 1)


@pytest.mark.parametrize(
    "packets",
    [
        [*FIN_CLOSE, (["SYN", "ACK"], FROM_SERVER)],
        [(["SYN"], FROM_CLIENT), (["SYN"], FROM_CLIENT)],
        [*HANDSHAKE, (["SYN"], FROM_CLIENT)],
    ],
)
def test_a_packet_that_is_not_a_new_connection_joins_the_flow(packets: list) -> None:
    tracker = FlowTracker()

    ids, exported = _send(tracker, packets)

    assert exported == []
    assert len(set(ids)) == 1
    assert [flow["packet_count"] for flow in tracker.flush()] == [len(packets)]


def test_flows_that_start_at_the_same_time_on_the_same_5_tuple_get_different_ids() -> None:
    tracker = FlowTracker()
    syn, reset = (["SYN"], FROM_CLIENT), (["RST"], FROM_SERVER)

    ids, _ = _send(tracker, [syn, reset, syn, reset, syn], step=0.0)

    assert ids[0] == KNOWN_ID
    assert len({ids[0], ids[2], ids[4]}) == 3


def test_a_reuse_at_the_flow_limit_evicts_nothing() -> None:
    tracker = FlowTracker(max_flows=1)
    _send(tracker, [(["SYN"], FROM_CLIENT), (["RST"], FROM_SERVER)])

    _, exported = _send(tracker, [(["SYN"], FROM_CLIENT)], at=START + 10)

    assert [flow["end_reason"] for flow in exported] == ["new_connection"]


def test_one_call_exports_the_expired_flow_before_the_reused_flow() -> None:
    tracker = FlowTracker(tcp_timeout=100.0)
    tracker.update(_view(("10.0.0.9", 1), SERVER, timestamp=START))
    _send(tracker, [(["SYN"], FROM_CLIENT), (["RST"], FROM_SERVER)], at=START + 50, step=10.0)

    _, exported = _send(tracker, [(["SYN"], FROM_CLIENT)], at=START + 150)

    assert [(flow["end_reason"], flow["endpoint_a"]["port"]) for flow in exported] == [
        ("idle_timeout", 1), ("new_connection", 40000)
    ]
