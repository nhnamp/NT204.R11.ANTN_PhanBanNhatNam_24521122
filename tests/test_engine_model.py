import json
from ipaddress import IPv4Network

from ids.engine.model import (
    Content,
    DsizeOption,
    FlagsOption,
    FlowOption,
    MatchedItem,
    MatchResult,
    ParsedRule,
    PortRange,
    Rule,
    RuleMatch,
)

RULE = Rule(
    sid=100001, rev=1, msg="Directory traversal", action="alert", protocol="tcp",
    src_ip=None, src_port=None, direction="->",
    dst_ip=IPv4Network("192.168.1.0/24"), dst_port=PortRange(80, 80),
    contents=(Content("../", b"../", nocase=True, depth=64),),
    flow=FlowOption("to_server", True), flags=FlagsOption(frozenset({"PSH", "ACK"}), "+"),
    dsize=DsizeOption("<>", 10, 500), classtype="web-application-attack", priority=1,
    origin="local.rules:3",
)


def test_rule_report_line_is_plain_json() -> None:
    line = json.loads(json.dumps(ParsedRule("local.rules", 3, "alert tcp ...", "valid", None, RULE).to_dict()))
    rule = line["rule"]

    assert rule["dst_ip"] == "192.168.1.0/24"
    assert rule["dst_port"] == {"low": 80, "high": 80}
    assert rule["src_ip"] is None
    assert rule["contents"][0]["pattern"] == "2e2e2f"
    assert rule["flags"] == {"flags": ["PSH", "ACK"], "modifier": "+"}


def test_rule_match_record_is_plain_json() -> None:
    match = RuleMatch(
        1758441600.0, "2025-09-21T08:00:00+00:00", 100001, 1, "Directory traversal", None, 1,
        "TCP", "10.0.0.5", 52133, "192.168.1.20", 80, "HTTP", "tcp-5f8ec36d79cc", "forward",
        "ESTABLISHED", 4, "pcap:x.pcap", (MatchedItem("content", "../", 12),),
    )

    record = json.loads(json.dumps(match.to_dict()))

    assert record["matched"] == [{"keyword": "content", "value": "../", "position": 12}]


def test_match_result_verdict() -> None:
    assert MatchResult(100001, True).verdict == "MATCH"
    assert MatchResult(100001, False, "header").verdict == "NO_MATCH"
