"""Tests for the flow tracker: key, direction, and flow id."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from ids.config import Config
from ids.enrich import Enricher
from ids.stages.flow import FlowTracker

ROOT = Path(__file__).parent.parent
CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)
KNOWN_ID = "tcp-5f8ec36d79cc"


def _view(
    source=CLIENT, destination=SERVER, protocol="TCP", flags=(), timestamp=1758441600.0,
    length=60, app_protocol="UNKNOWN", method=None,
) -> dict:
    return {
        "protocol": protocol,
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "tcp_flags": list(flags),
        "timestamp": timestamp,
        "length": length,
        "app_protocol": app_protocol,
        "detection_method": method,
    }


def _update(tracker: FlowTracker, view: dict) -> tuple[str, str]:
    flow_id, direction, exported = tracker.update(view)
    assert exported == []
    return flow_id, direction


def test_the_two_directions_belong_to_one_flow() -> None:
    tracker = FlowTracker()

    first = _update(tracker, _view())
    second = _update(tracker, _view(SERVER, CLIENT, timestamp=1758441601.0))

    assert first[0] == second[0]
    assert (first[1], second[1]) == ("forward", "backward")


@pytest.mark.parametrize(
    ("protocol", "flags", "first", "second"),
    [
        ("TCP", ["SYN"], "forward", "backward"),
        ("TCP", ["SYN", "ACK"], "backward", "forward"),
        ("TCP", ["PSH", "ACK"], "forward", "backward"),
        ("UDP", [], "forward", "backward"),
        ("UDP", ["SYN", "ACK"], "forward", "backward"),
    ],
    ids=["syn-first", "syn-ack-first", "data-first", "udp", "udp-with-tcp-flags"],
)
def test_the_first_packet_decides_who_started_the_flow(protocol: str, flags: list[str], first: str, second: str) -> None:
    tracker = FlowTracker()

    directions = [
        _update(tracker, _view(protocol=protocol, flags=flags))[1],
        _update(tracker, _view(SERVER, CLIENT, protocol=protocol))[1],
    ]

    assert directions == [first, second]


@pytest.mark.parametrize(
    "other",
    [
        _view(protocol="UDP"),
        _view(destination=("10.0.0.2", 81)),
        _view(source=("10.0.0.3", 40000)),
        _view(source=("10.0.0.1", 40001)),
    ],
    ids=["protocol", "port", "ip", "source-port"],
)
def test_a_different_protocol_address_or_port_is_another_flow(other: dict) -> None:
    tracker = FlowTracker()

    assert _update(tracker, _view())[0] != _update(tracker, other)[0]


@pytest.mark.parametrize(
    "view",
    [_view(), _view(flags=["SYN"]), _view(SERVER, CLIENT, flags=["SYN", "ACK"])],
    ids=["data-first", "syn-first", "syn-ack-first"],
)
def test_the_flow_id_has_a_fixed_value(view: dict) -> None:
    assert _update(FlowTracker(), view)[0] == KNOWN_ID


def test_the_flow_id_does_not_depend_on_the_hash_seed() -> None:
    code = (
        "from ids.stages.flow import FlowTracker\n"
        "view = dict(protocol='TCP', src_ip='10.0.0.1', src_port=40000, dst_ip='10.0.0.2', dst_port=80,\n"
        "            tcp_flags=[], timestamp=1758441600.0, length=60, app_protocol='UNKNOWN', detection_method=None)\n"
        "print(FlowTracker().update(view)[0])"
    )

    ids = {
        subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed},
        ).stdout.strip()
        for seed in ("1", "2")
    }

    assert ids == {KNOWN_ID}


def test_the_enricher_sets_the_flow_id_and_the_direction_of_a_kept_record() -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", "keep", None))
    request = {
        "timestamp": 1758441600.0,
        "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80, "flags": ["SYN"]},
    }
    reply = {**request, "network": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1"},
             "transport": {"protocol": "TCP", "src_port": 80, "dst_port": 40000, "flags": ["SYN", "ACK"]}}
    arp = {"timestamp": 1758441600.0}

    first, _ = enricher.process(request)
    second, _ = enricher.process(reply)
    skipped, _ = enricher.process(arp)

    assert (first["flow_id"], first["direction"]) == (KNOWN_ID, "forward")
    assert (second["flow_id"], second["direction"]) == (KNOWN_ID, "backward")
    assert (skipped["flow_id"], skipped["direction"]) == (None, None)


def _flush(*views: dict) -> list[dict]:
    tracker = FlowTracker()
    for view in views:
        tracker.update(view)
    return tracker.flush()


def test_a_udp_flow_counts_both_directions() -> None:
    query = _view(protocol="UDP", timestamp=100.0, length=71, app_protocol="DNS", method="port+payload")
    response = _view(SERVER, CLIENT, protocol="UDP", timestamp=100.0004567, length=87, app_protocol="DNS", method="port+payload")

    repeat = _view(protocol="UDP", timestamp=100.0002, length=70, app_protocol="DNS", method="port+payload")

    (flow,) = _flush(query, repeat, response)

    assert (flow["packet_count"], flow["byte_count"]) == (3, 228)
    assert (flow["forward_packet_count"], flow["forward_byte_count"]) == (2, 141)
    assert (flow["backward_packet_count"], flow["backward_byte_count"]) == (1, 87)
    assert (flow["start_time"], flow["last_seen"], flow["duration"]) == (100.0, 100.0004567, 0.000457)
    assert flow["application_protocol"] == "DNS"
    assert flow["end_reason"] == "end_of_input"
    assert (flow["syn_count"], flow["ack_count"], flow["fin_count"], flow["rst_count"], flow["state"]) == (None,) * 5


def test_a_tcp_packet_adds_one_to_each_flag_it_carries() -> None:
    flag_sets = [["SYN"], ["SYN", "ACK"], ["ACK"], ["PSH", "ACK"], [], ["FIN", "ACK"], ["FIN"], ["RST"]]
    views = [_view(flags=flags, timestamp=float(i)) for i, flags in enumerate(flag_sets)]

    (flow,) = _flush(*views)

    assert (flow["syn_count"], flow["ack_count"], flow["fin_count"], flow["rst_count"]) == (2, 4, 2, 1)
    assert flow["state"] is None


def test_last_seen_keeps_the_largest_timestamp_when_packets_arrive_out_of_order() -> None:
    (flow,) = _flush(_view(timestamp=10.0), _view(timestamp=5.0), _view(timestamp=12.0), _view(timestamp=7.0))

    assert (flow["start_time"], flow["last_seen"], flow["duration"]) == (10.0, 12.0, 2.0)


def test_a_packet_without_a_length_counts_zero_bytes() -> None:
    (flow,) = _flush(_view(length=None), _view(length=0), _view(length=10))

    assert (flow["packet_count"], flow["byte_count"]) == (3, 10)


@pytest.mark.parametrize(
    ("detections", "expected"),
    [
        ([("HTTP", "port")], "HTTP"),
        ([("HTTP", "payload")], "HTTP"),
        ([("HTTP", None)], "UNKNOWN"),
        ([("HTTP", "none")], "UNKNOWN"),
        ([("UNKNOWN", "payload")], "UNKNOWN"),
        ([("HTTP", "port"), ("DNS", "port+payload")], "DNS"),
        ([("DNS", "payload"), ("HTTP", "port")], "DNS"),
        ([("HTTP", "port"), ("DNS", "port")], "HTTP"),
        ([("DNS", "port+payload"), ("SMTP", "payload")], "DNS"),
        ([("UNKNOWN", "none"), ("SMTP", "port")], "SMTP"),
        ([("UNKNOWN", "payload"), ("HTTP", "port")], "HTTP"),
    ],
    ids=[
        "port", "payload", "no-method", "method-none", "unknown-protocol",
        "payload-beats-port", "no-downgrade", "first-of-equal-rank", "first-payload-wins", "late-detection", "unknown-rank-zero",
    ],
)
def test_the_flow_keeps_the_first_detection_of_the_highest_rank(detections: list[tuple], expected: str) -> None:
    views = [_view(app_protocol=protocol, method=method) for protocol, method in detections]

    assert _flush(*views)[0]["application_protocol"] == expected


def test_flush_empties_the_table_and_orders_flows_by_start_time() -> None:
    tracker = FlowTracker()
    tracker.update(_view(CLIENT, SERVER, timestamp=5.0))
    tracker.update(_view(("10.0.0.3", 1), SERVER, timestamp=1.0))
    tracker.update(_view(("10.0.0.4", 1), SERVER, timestamp=5.0))

    flows = tracker.flush()

    assert [(flow["endpoint_a"]["ip"], flow["start_time"]) for flow in flows] == [
        ("10.0.0.3", 1.0), ("10.0.0.1", 5.0), ("10.0.0.4", 5.0),
    ]
    assert tracker.flush() == []


def test_the_enricher_flush_exports_the_flows_once() -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", "keep", None))
    record = {
        "timestamp": 1758441600.0,
        "length": 54,
        "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80, "flags": ["SYN"]},
    }
    enricher.process(record)

    flows = enricher.flush()

    assert [(flow["flow_id"], flow["packet_count"], flow["syn_count"]) for flow in flows] == [(KNOWN_ID, 1, 1)]
    assert enricher.flush() == []
