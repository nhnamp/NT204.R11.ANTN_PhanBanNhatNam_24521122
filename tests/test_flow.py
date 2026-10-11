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


def _view(source=CLIENT, destination=SERVER, protocol="TCP", flags=(), timestamp=1758441600.0) -> dict:
    return {
        "protocol": protocol,
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "tcp_flags": list(flags),
        "timestamp": timestamp,
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
        "            tcp_flags=[], timestamp=1758441600.0)\n"
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
