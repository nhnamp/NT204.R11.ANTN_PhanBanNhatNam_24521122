import json
from ipaddress import IPv4Network

from ids.engine.generator import build_rule_match
from ids.engine.model import Content, MatchedItem, MatchResult, PortRange, Rule
from ids.stages.flow import FlowContext

RULE = Rule(
    sid=100001, rev=2, msg="Directory traversal", action="alert", protocol="tcp", src_ip=None, src_port=None,
    direction="->", dst_ip=IPv4Network("10.0.0.0/24"), dst_port=PortRange(80, 80),
    contents=(Content("../", b"../"),), classtype="web-application-attack", priority=1,
)
RECORD = {
    "packet_id": 7,
    "source": "pcap:a.pcap",
    "normalized": {
        "timestamp": 1758441600.0, "timestamp_iso": "2025-09-21T08:00:00+00:00", "protocol": "TCP",
        "src_ip": "192.168.1.5", "src_port": 40000, "dst_ip": "10.0.0.9", "dst_port": 80, "app_protocol": "HTTP",
    },
}
RESULT = MatchResult(100001, True, items=(MatchedItem("content", "../", 9),))


def test_the_record_has_every_field_with_its_value():
    flow = FlowContext("tcp-abc", "forward", "ESTABLISHED", 3, 2)
    assert build_rule_match(RULE, RECORD, flow, RESULT).to_dict() == {
        "timestamp": 1758441600.0, "timestamp_iso": "2025-09-21T08:00:00+00:00",
        "sid": 100001, "rev": 2, "msg": "Directory traversal",
        "classtype": "web-application-attack", "priority": 1,
        "protocol": "TCP", "src_ip": "192.168.1.5", "src_port": 40000, "dst_ip": "10.0.0.9", "dst_port": 80,
        "application_protocol": "HTTP", "flow_id": "tcp-abc", "direction": "forward", "flow_state": "ESTABLISHED",
        "packet_id": 7, "source": "pcap:a.pcap",
        "matched": [{"keyword": "content", "value": "../", "position": 9}],
    }


def test_flow_fields_are_none_without_a_flow_context():
    data = build_rule_match(RULE, RECORD, None, RESULT).to_dict()
    assert (data["flow_id"], data["direction"], data["flow_state"]) == (None, None, None)
    json.dumps(data)
