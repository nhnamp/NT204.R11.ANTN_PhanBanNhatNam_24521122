from ipaddress import IPv4Network

import pytest

from ids.engine.matcher import match
from ids.engine.model import PortRange, Rule


def rule(**changes):
    fields = dict(
        sid=1, rev=1, msg="test", action="alert", protocol="tcp",
        src_ip=None, src_port=None, direction="->", dst_ip=IPv4Network("10.0.0.0/24"), dst_port=PortRange(80, 80),
    )
    return Rule(**{**fields, **changes})


def record(**changes):
    normalized = dict(
        protocol="TCP", src_ip="192.168.1.5", src_port=40000, dst_ip="10.0.0.9", dst_port=80, tcp_flags=[], payload_len=0,
    )
    return {"normalized": {**normalized, **changes}}


def test_header_matches_and_reports_the_failed_stage():
    assert match(rule(), record(), b"", None).matched
    result = match(rule(), record(dst_port=81), b"", None)
    assert (result.verdict, result.failed_stage, result.sid) == ("NO_MATCH", "header", 1)
    assert match(rule(), record(protocol="UDP"), b"", None).failed_stage == "header"
    assert match(rule(dst_ip=IPv4Network("10.0.1.0/24")), record(), b"", None).failed_stage == "header"


def test_ip_rule_matches_tcp_and_udp_and_port_range_is_inclusive():
    ip_rule = rule(protocol="ip", dst_port=PortRange(80, 90))
    assert match(ip_rule, record(protocol="UDP", dst_port=90), b"", None).matched
    assert match(ip_rule, record(dst_port=91), b"", None).failed_stage == "header"


@pytest.mark.parametrize("direction, reply_matches", [("->", False), ("<>", True)])
def test_direction_arrow_and_bidirectional(direction, reply_matches):
    reply = record(src_ip="10.0.0.9", src_port=80, dst_ip="192.168.1.5", dst_port=40000)
    assert match(rule(direction=direction), record(), b"", None).matched
    assert match(rule(direction=direction), reply, b"", None).matched is reply_matches
