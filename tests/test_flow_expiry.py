"""Tests for the idle timeout: when a flow expires, what leaves the table, and in which order."""

import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run
from ids.stages import flow as flow_module
from ids.stages.flow import FlowTracker

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _packet(client_port: int, timestamp: float, protocol: str = "UDP") -> dict:
    return {
        "protocol": protocol,
        "src_ip": "10.0.0.1",
        "src_port": client_port,
        "dst_ip": "10.0.0.2",
        "dst_port": 53,
        "tcp_flags": [],
        "timestamp": timestamp,
        "length": 60,
        "app_protocol": "UNKNOWN",
        "detection_method": None,
    }


def _exported(tracker: FlowTracker, *packets: dict) -> list[dict]:
    """Feed the packets and return every flow that left the table, with its end reason."""
    exported: list[dict] = []
    for packet in packets:
        exported += tracker.update(packet)[2]
    return exported


@pytest.mark.parametrize(("gap", "expired"), [(30.0, False), (30.000001, True)])
def test_a_flow_expires_only_when_the_gap_is_longer_than_the_timeout(gap: float, expired: bool) -> None:
    tracker = FlowTracker(udp_timeout=30.0)

    exported = _exported(tracker, _packet(1, 100.0), _packet(2, 100.0 + gap))

    assert [flow["end_reason"] for flow in exported] == (["idle_timeout"] if expired else [])


def test_an_expired_flow_leaves_the_table_and_the_next_packet_starts_a_new_flow() -> None:
    tracker = FlowTracker(udp_timeout=30.0)
    first_id = tracker.update(_packet(1, 100.0))[0]

    _, _, exported = tracker.update(_packet(2, 200.0))
    second_id = tracker.update(_packet(1, 200.5))[0]

    (expired,) = exported
    assert (expired["flow_id"], expired["packet_count"], expired["last_seen"]) == (first_id, 1, 100.0)
    assert second_id != first_id
    assert [flow["packet_count"] for flow in tracker.flush()] == [1, 1]


def test_a_packet_of_an_expired_flow_starts_a_new_flow_instead_of_joining_it() -> None:
    tracker = FlowTracker(udp_timeout=30.0)
    first_id = tracker.update(_packet(1, 100.0))[0]

    second_id, _, exported = tracker.update(_packet(1, 200.0))

    assert [flow["flow_id"] for flow in exported] == [first_id]
    assert second_id != first_id
    assert [flow["packet_count"] for flow in tracker.flush()] == [1]


@pytest.mark.parametrize(("protocol", "survives"), [("TCP", True), ("UDP", False)])
def test_tcp_and_udp_flows_use_their_own_timeouts(protocol: str, survives: bool) -> None:
    tracker = FlowTracker(tcp_timeout=100.0, udp_timeout=10.0)

    exported = _exported(tracker, _packet(1, 0.0, protocol), _packet(2, 50.0, "TCP"))

    assert [flow["end_reason"] for flow in exported] == ([] if survives else ["idle_timeout"])


def test_a_late_packet_does_not_put_an_older_flow_behind_a_newer_one() -> None:
    tracker = FlowTracker(udp_timeout=30.0)

    # The packet at 3.0 starts a flow behind the flow at 10.0, and the clock stays at 10.0 for the packet at 5.0.
    exported = _exported(
        tracker, _packet(1, 1.0), _packet(2, 10.0), _packet(3, 3.0), _packet(1, 5.0), _packet(4, 40.0)
    )

    assert [flow["last_seen"] for flow in exported] == [5.0]


def test_one_future_packet_ends_the_flows_of_the_other_table_but_not_the_flows_behind_it() -> None:
    tracker = FlowTracker()

    # The clock stays at 1000.0. The UDP flow expires at its next packet, and the TCP flow stands behind the future flow.
    exported = _exported(
        tracker,
        _packet(1, 1000.0, "TCP"), _packet(2, 0.0, "TCP"), _packet(3, 0.0, "UDP"), _packet(2, 1.0, "TCP"), _packet(3, 1.0, "UDP"),
    )

    assert [(flow["protocol"], flow["packet_count"]) for flow in exported] == [("UDP", 1)]
    assert sorted((flow["protocol"], flow["packet_count"]) for flow in tracker.flush()) == [("TCP", 1), ("TCP", 2), ("UDP", 1)]


def test_flows_that_expire_together_leave_in_the_order_of_their_last_packet() -> None:
    tracker = FlowTracker()

    exported = _exported(
        tracker,
        _packet(1, 5.0, "UDP"), _packet(2, 5.0, "TCP"), _packet(3, 3.0, "UDP"), _packet(4, 1000.0, "UDP"),
    )

    assert [(flow["protocol"], flow["last_seen"]) for flow in exported] == [("UDP", 3.0), ("UDP", 5.0), ("TCP", 5.0)]


def test_flush_keeps_creation_order_when_a_tcp_flow_and_a_udp_flow_start_together() -> None:
    tracker = FlowTracker()
    _exported(tracker, _packet(1, 5.0, "UDP"), _packet(2, 5.0, "TCP"))

    assert [flow["protocol"] for flow in tracker.flush()] == ["UDP", "TCP"]


def _fail(*args: object) -> None:
    raise RuntimeError("after the removal")


@pytest.mark.parametrize("next_call", ["update", "flush"])
def test_the_flows_that_left_the_table_arrive_even_when_the_call_fails_afterwards(
    monkeypatch: pytest.MonkeyPatch, next_call: str
) -> None:
    tracker = FlowTracker(udp_timeout=30.0)
    first_id = tracker.update(_packet(1, 0.0))[0]
    with monkeypatch.context() as patch:
        patch.setattr(flow_module, "_count", _fail)
        with pytest.raises(RuntimeError):
            tracker.update(_packet(2, 100.0))

    exported = tracker.update(_packet(3, 100.5))[2] if next_call == "update" else tracker.flush()

    assert [(flow["flow_id"], flow["end_reason"]) for flow in exported] == [(first_id, "idle_timeout")]
    assert tracker.update(_packet(4, 101.0))[2] == []


def test_a_failure_while_expiring_keeps_every_flow_and_exports_each_one_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tracker = FlowTracker(udp_timeout=30.0)
    _exported(tracker, _packet(1, 0.0), _packet(2, 1.0))
    build = flow_module._record
    calls = []

    def fail_on_the_second_record(flow: object, end_reason: str) -> dict:
        calls.append(flow)
        if len(calls) == 2:
            raise RuntimeError("second record")
        return build(flow, end_reason)

    with monkeypatch.context() as patch:
        patch.setattr(flow_module, "_record", fail_on_the_second_record)
        with pytest.raises(RuntimeError):
            tracker.update(_packet(3, 100.0))

    exported = tracker.update(_packet(3, 100.5))[2]

    assert [flow["start_time"] for flow in exported] == [0.0, 1.0]


def test_a_bad_packet_changes_neither_the_clock_nor_the_table() -> None:
    tracker = FlowTracker(udp_timeout=30.0)
    tracker.update(_packet(1, 0.0))
    bad = _packet(2, 100.0)
    del bad["tcp_flags"]

    with pytest.raises(KeyError):
        tracker.update(bad)

    assert tracker.update(_packet(1, 10.0))[2] == []
    assert [flow["packet_count"] for flow in tracker.flush()] == [2]


@pytest.mark.parametrize(
    ("name", "option", "flows"),
    [("dns_udp_flow.pcap", "--udp-timeout", 2), ("flow_http.pcap", "--tcp-timeout", 7)],
)
def test_the_timeout_options_reach_the_tracker(tmp_path: Path, name: str, option: str, flows: int) -> None:
    def run_with(*extra: str) -> list[dict]:
        output = tmp_path / "flows.jsonl"
        arguments = ["--pcap", str(FIXTURE_DIR / name), "--output", str(tmp_path / "out.jsonl"), "--flows-output", str(output)]
        assert run(parse_args([*arguments, *extra])) == 0
        return [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

    assert len(run_with()) == 1
    short = run_with(option, "0.25")
    assert len(short) == flows
    assert {flow["end_reason"] for flow in short} == {"idle_timeout", "end_of_input"}
