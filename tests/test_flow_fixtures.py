"""Tests that run the flow fixtures through the CLI and read the flows file."""

import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run
from tests.fixtures.build_pcaps import expected_flow_stats

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _run(name: str, tmp_path: Path) -> tuple[list[dict], list[dict]]:
    output, flows = tmp_path / "out.jsonl", tmp_path / "flows.jsonl"
    arguments = ["--pcap", str(FIXTURE_DIR / name), "--output", str(output), "--flows-output", str(flows)]
    assert run(parse_args(arguments)) == 0
    return (
        [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()],
        [json.loads(line) for line in flows.read_text(encoding="utf-8").splitlines()],
    )


def test_a_dns_query_and_its_response_form_one_udp_flow(tmp_path: Path) -> None:
    records, flows = _run("dns_udp_flow.pcap", tmp_path)

    (flow,) = flows
    assert flow["protocol"] == "UDP"
    assert flow["application_protocol"] == "DNS"
    assert (flow["packet_count"], flow["forward_packet_count"], flow["backward_packet_count"]) == (2, 1, 1)
    assert flow["byte_count"] == sum(record["length"] for record in records)
    assert (flow["forward_byte_count"], flow["backward_byte_count"]) == (records[0]["length"], records[1]["length"])
    assert [(r["flow_id"], r["direction"]) for r in records] == [(flow["flow_id"], "forward"), (flow["flow_id"], "backward")]
    assert (flow["endpoint_a"], flow["endpoint_b"]) == ({"ip": "10.0.0.1", "port": 40000}, {"ip": "10.0.0.2", "port": 53})
    assert (flow["syn_count"], flow["state"], flow["end_reason"]) == (None, None, "end_of_input")


def test_one_connection_is_one_flow_and_the_directions_follow_the_packets(tmp_path: Path) -> None:
    records, flows = _run("flow_http.pcap", tmp_path)

    (flow,) = flows
    assert {record["flow_id"] for record in records} == {flow["flow_id"]}
    assert [record["direction"] for record in records] == ["forward", "backward", "forward", "forward", "backward", "backward", "forward"]
    assert (flow["application_protocol"], flow["state"], flow["packet_count"]) == ("HTTP", "ESTABLISHED", 7)


@pytest.mark.parametrize(
    ("name", "state", "fin_count", "rst_count"),
    [("tcp_close_fin.pcap", "CLOSED", 2, 0), ("tcp_close_rst.pcap", "RESET", 0, 1)],
)
def test_a_close_and_a_reset_end_in_their_own_state(name: str, state: str, fin_count: int, rst_count: int, tmp_path: Path) -> None:
    _, flows = _run(name, tmp_path)

    (flow,) = flows
    assert (flow["state"], flow["fin_count"], flow["rst_count"]) == (state, fin_count, rst_count)


def test_interleaved_connections_keep_their_packets_apart(tmp_path: Path) -> None:
    records, flows = _run("concurrent_flows.pcap", tmp_path)

    assert len({flow["flow_id"] for flow in flows}) == 4
    assert {flow["endpoint_a"]["port"]: flow["packet_count"] for flow in flows} == {40000: 4, 40001: 3, 40002: 3, 40003: 2}
    endpoints = {
        flow["flow_id"]: {(flow[side]["ip"], flow[side]["port"]) for side in ("endpoint_a", "endpoint_b")} for flow in flows
    }
    for record in records:
        packet = {(record["network"]["src_ip"], record["transport"]["src_port"]), (record["network"]["dst_ip"], record["transport"]["dst_port"])}
        assert endpoints[record["flow_id"]] == packet


def test_the_flow_counters_equal_the_values_computed_from_the_packets(tmp_path: Path) -> None:
    _, flows = _run("flow_stats.pcap", tmp_path)

    (flow,) = flows
    expected = expected_flow_stats()
    assert {key: flow[key] for key in expected} == expected
    assert flow["state"] == "CLOSED"
