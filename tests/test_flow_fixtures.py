"""Tests that run the flow fixtures through the CLI and read the flows file."""

import json
from pathlib import Path

from ids.cli import parse_args, run

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
