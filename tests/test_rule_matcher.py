from ipaddress import IPv4Network

import pytest

from ids.engine import matcher
from ids.engine.matcher import match
from ids.engine.model import Content, DsizeOption, FlagsOption, FlowOption, PortRange, Rule
from ids.stages.flow import FlowContext


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


def flow_context(direction="forward", state="ESTABLISHED", forward_packets=1, backward_packets=1):
    return FlowContext("flow-1", direction, state, forward_packets, backward_packets)


def test_flow_to_server_established_follows_direction_and_state():
    flow_rule = rule(flow=FlowOption("to_server", True))
    assert match(flow_rule, record(), b"", flow_context()).matched
    assert match(flow_rule, record(), b"", flow_context(state="HANDSHAKE")).failed_stage == "flow"
    assert match(flow_rule, record(), b"", flow_context(direction="backward")).failed_stage == "flow"
    assert match(flow_rule, record(), b"", flow_context(state="CLOSING")).matched
    assert match(flow_rule, record(), b"", flow_context(state="RESET")).failed_stage == "flow"


def test_flow_not_established_and_to_client():
    assert match(rule(flow=FlowOption(None, False)), record(), b"", flow_context(state="HANDSHAKE")).matched
    assert match(rule(flow=FlowOption("to_client", None)), record(), b"", flow_context("backward")).matched


def test_flow_option_needs_a_flow_context():
    assert match(rule(flow=FlowOption("to_server", None)), record(), b"", None).failed_stage == "flow"
    assert match(rule(), record(), b"", None).matched


def test_udp_established_needs_packets_in_both_directions():
    udp_rule = rule(protocol="udp", flow=FlowOption(None, True))
    assert match(udp_rule, record(protocol="UDP"), b"", flow_context(state=None)).matched
    one_way = flow_context(state=None, backward_packets=0)
    assert match(udp_rule, record(protocol="UDP"), b"", one_way).failed_stage == "flow"


def test_header_mismatch_stops_before_flow():
    result = match(rule(flow=FlowOption("to_server", None)), record(dst_port=81), b"", None)
    assert result.failed_stage == "header"


def content(text, **modifiers):
    return Content(text, text.encode(), **modifiers)


def test_content_is_case_sensitive_unless_nocase():
    payload = b"GET /Admin HTTP/1.1"
    assert match(rule(contents=(content("/Admin"),)), record(), payload, None).matched
    exact = match(rule(contents=(content("/admin"),)), record(), payload, None)
    assert (exact.matched, exact.failed_stage) == (False, "content")
    folded = match(rule(contents=(content("/admin", nocase=True),)), record(), payload, None)
    assert [(item.keyword, item.value, item.position) for item in folded.items] == [("content", "/admin", 4)]


def test_offset_and_depth_limit_the_region_from_the_buffer_start():
    payload = b"xxGETxxxxxxxxxxGET"
    assert match(rule(contents=(content("GET", offset=2, depth=3),)), record(), payload, None).matched
    assert match(rule(contents=(content("GET", offset=3),)), record(), payload, None).items[0].position == 15
    assert not match(rule(contents=(content("GET", depth=4),)), record(), payload, None).matched
    assert not match(rule(contents=(content("GET", offset=3, depth=5),)), record(), payload, None).matched


def test_distance_and_within_start_at_the_end_of_the_previous_content():
    payload = b"USER bob PASS secret"
    chain = lambda **modifiers: rule(contents=(content("USER"), content("PASS", **modifiers)))
    assert match(chain(distance=1, within=9), record(), payload, None).matched
    assert not match(chain(distance=6), record(), payload, None).matched
    assert not match(chain(within=8), record(), payload, None).matched


def test_relative_content_tries_a_later_occurrence_of_the_first_content():
    payload = b"AB.xxxxxxxxAB..CD"
    result = match(rule(contents=(content("AB"), content("CD", distance=2, within=2))), record(), payload, None)
    assert [item.position for item in result.items] == [11, 15]


def test_header_mismatch_does_not_run_content_matching(monkeypatch):
    def fail(*args):
        raise AssertionError("content matching ran")

    monkeypatch.setattr(matcher, "_content_positions", fail)
    assert match(rule(contents=(content("x"),)), record(dst_port=81), b"x", None).failed_stage == "header"


def flags_rule(flags, modifier=""):
    return rule(flags=FlagsOption(frozenset(flags), modifier))


@pytest.mark.parametrize(
    "flags, modifier, present, expected",
    [
        (["SYN"], "", ["SYN"], True),
        (["SYN"], "", ["SYN", "ACK"], False),
        (["SYN"], "+", ["SYN", "ACK"], True),
        (["SYN", "ACK"], "+", ["SYN"], False),
        (["SYN", "FIN"], "*", ["ACK", "FIN"], True),
        (["SYN", "FIN"], "*", ["ACK"], False),
        (["RST"], "!", ["ACK"], True),
        (["RST"], "!", ["RST", "ACK"], False),
        ([], "", [], True),
        ([], "", ["ACK"], False),
    ],
)
def test_flags_modes(flags, modifier, present, expected):
    result = match(flags_rule(flags, modifier), record(tcp_flags=present), b"", None)
    assert result.matched is expected
    assert result.failed_stage == (None if expected else "packet")


def test_flags_never_match_udp():
    assert not match(rule(protocol="udp", flags=FlagsOption(frozenset())), record(protocol="UDP"), b"", None).matched


@pytest.mark.parametrize(
    "option, size, expected",
    [
        (DsizeOption("=", 10), 10, True),
        (DsizeOption("=", 10), 11, False),
        (DsizeOption(">", 10), 10, False),
        (DsizeOption(">", 10), 11, True),
        (DsizeOption("<", 10), 9, True),
        (DsizeOption("<", 10), 10, False),
        (DsizeOption("<>", 10, 20), 10, True),
        (DsizeOption("<>", 10, 20), 20, True),
        (DsizeOption("<>", 10, 20), 21, False),
    ],
)
def test_dsize_forms_at_their_limits(option, size, expected):
    assert match(rule(dsize=option), record(payload_len=size), b"", None).matched is expected


def test_packet_stage_runs_before_content_and_reports_its_items():
    packet_rule = rule(flags=FlagsOption(frozenset({"PSH", "ACK"}), "+"), dsize=DsizeOption(">", 2), contents=(content("ab"),))
    packet = record(tcp_flags=["ACK", "PSH"], payload_len=4)
    assert [(i.keyword, i.value) for i in match(packet_rule, packet, b"xxab", None).items] == [
        ("flags", "+PSH,ACK"), ("dsize", ">2"), ("content", "ab"),
    ]
    assert match(packet_rule, record(tcp_flags=["ACK"], payload_len=4), b"xxab", None).failed_stage == "packet"
