import json
import random
import string
from ipaddress import IPv4Network

import pytest

from ids.engine.model import Content, DsizeOption, FlagsOption, FlowOption, PortRange
from ids.engine.parser import parse_rule

BODY = 'msg:"test"; sid:1;'


def parse(header, body=BODY):
    return parse_rule("local.rules", 3, f"{header} ({body})")


def rule_of(header, body=BODY):
    parsed = parse(header, body)
    assert parsed.status == "valid", parsed.reason
    return parsed.rule


def test_valid_rule_keeps_every_field():
    parsed = parse_rule(
        "local.rules", 7,
        'alert tcp 10.0.0.0/24 any -> 192.168.1.20 80 (msg:"Traversal; \\"x\\""; flow:to_server,established; '
        'content:"../"; nocase; offset:2; depth:20; content:"|0D 0A|ab"; distance:1; within:10; '
        "flags:SA+; dsize:>10; classtype:web-attack; priority:1; sid:100001; rev:2;)",
    )
    rule = parsed.rule
    assert (parsed.status, parsed.reason, parsed.file, parsed.line) == ("valid", None, "local.rules", 7)
    assert (rule.sid, rule.rev, rule.msg, rule.origin) == (100001, 2, 'Traversal; "x"', "local.rules:7")
    assert rule.src_ip == IPv4Network("10.0.0.0/24") and rule.dst_ip == IPv4Network("192.168.1.20/32")
    assert rule.src_port is None and rule.dst_port == PortRange(80, 80)
    assert rule.flow == FlowOption("to_server", True)
    assert rule.flags == FlagsOption(frozenset({"SYN", "ACK"}), "+")
    assert rule.dsize == DsizeOption(">", 10)
    assert (rule.classtype, rule.priority) == ("web-attack", 1)
    assert rule.contents == (
        Content("../", b"../", nocase=True, offset=2, depth=20),
        Content("|0D 0A|ab", b"\r\nab", distance=1, within=10),
    )


def test_defaults_and_ip_protocol():
    rule = rule_of("alert ip any any <> any any")
    assert (rule.rev, rule.classtype, rule.priority, rule.protocol, rule.direction) == (1, None, None, "ip", "<>")
    assert rule.src_ip is None and rule.src_port is None and rule.contents == ()


@pytest.mark.parametrize(
    "port, expected",
    [("any", None), ("80", PortRange(80, 80)), ("1000:2000", PortRange(1000, 2000)),
     ("1024:", PortRange(1024, 65535)), (":1023", PortRange(0, 1023))],
)
def test_port_forms(port, expected):
    assert rule_of(f"alert udp any any -> any {port}").dst_port == expected


@pytest.mark.parametrize(
    "header",
    [
        "alert tcp any any -> any",
        "alert tcp 999.1.1.1 any -> any 80",
        "alert tcp 10.0.0.0/33 any -> any 80",
        "alert tcp any 70000 -> any 80",
        "alert tcp any 90:80 -> any 80",
        "alert tcp any any <- any 80",
        "alert ip any any -> any 80",
        "alert sctp any any -> any 80",
    ],
)
def test_invalid_headers(header):
    parsed = parse(header)
    assert parsed.status == "invalid" and parsed.reason and parsed.rule is None


@pytest.mark.parametrize(
    "header",
    [
        "alert icmp any any -> any any",
        "alert tcp $HOME_NET any -> any 80",
        "alert tcp !10.0.0.1 any -> any 80",
        "alert tcp [10.0.0.1,10.0.0.2] any -> any 80",
        "alert tcp any any -> any [80,81]",
        "drop tcp any any -> any 80",
    ],
)
def test_unsupported_headers(header):
    parsed = parse(header)
    assert parsed.status == "unsupported" and parsed.reason and parsed.rule is None


@pytest.mark.parametrize(
    "body",
    [
        'msg:"x"',
        "sid:1",
        'msg:"x"; sid:abc',
        'msg:"x"; sid:1; sid:2',
        'msg:"x"; sid:1; nocase',
        'msg:"x"; sid:1; content:"abc"; depth:2',
        'msg:"x"; sid:1; content:"abc"; offset:1; distance:1',
        'msg:"x"; sid:1; content:"abc"; within:2',
        'msg:"x"; sid:1; content:abc',
        'msg:"x"; sid:1; content:"a|0G|"',
        'msg:"x"; sid:1; content:"a|0D"',
        'msg:"x"; sid:1; content:""',
        'msg:"x; sid:1',
        'msg:"x"; sid:1; flags:Z',
        'msg:"x"; sid:1; flags:S0',
        'msg:"x"; sid:1; dsize:abc',
        'msg:"x"; sid:1; dsize:10<>5',
        'msg:"x"; sid:1; flow:to_server,to_client',
    ],
)
def test_invalid_options(body):
    parsed = parse("alert tcp any any -> any 80", body)
    assert parsed.status == "invalid" and parsed.reason and parsed.rule is None


@pytest.mark.parametrize(
    "body",
    [
        'msg:"x"; sid:1; pcre:"/a/"',
        'msg:"x"; sid:1; byte_test:1,>,1,0',
        'msg:"x"; sid:1; http_uri',
        'msg:"x"; sid:1; content:!"abc"',
        'msg:"x"; sid:1; flags:S,CE',
        'msg:"x"; sid:1; flags:12',
        'msg:"x"; sid:1; flow:stateless',
    ],
)
def test_unsupported_options(body):
    parsed = parse("alert tcp any any -> any 80", body)
    assert parsed.status == "unsupported" and parsed.reason and parsed.rule is None


@pytest.mark.parametrize("text", ["", "   ", "alert", "alert tcp any any -> any 80", "alert tcp any any -> any 80 (", ")("])
def test_malformed_lines_are_invalid(text):
    parsed = parse_rule("f", 1, text)
    assert parsed.status == "invalid" and parsed.rule is None


@pytest.mark.parametrize(
    "value, flags, modifier",
    [("S", {"SYN"}, ""), ("FSRPAUCE", {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE"}, ""),
     ("0", set(), ""), ("A+", {"ACK"}, "+"), ("*SF", {"SYN", "FIN"}, "*"), ("!S", {"SYN"}, "!"), ("CE", {"CWR", "ECE"}, "")],
)
def test_flags_use_tcp_flag_names(value, flags, modifier):
    option = rule_of("alert tcp any any -> any 80", f"{BODY} flags:{value};").flags
    assert option == FlagsOption(frozenset(flags), modifier)


@pytest.mark.parametrize(
    "value, expected",
    [("10", DsizeOption("=", 10)), (">10", DsizeOption(">", 10)), ("<10", DsizeOption("<", 10)),
     ("5<>10", DsizeOption("<>", 5, 10)), ("5<>5", DsizeOption("<>", 5, 5))],
)
def test_dsize_forms(value, expected):
    assert rule_of("alert tcp any any -> any 80", f"{BODY} dsize:{value};").dsize == expected


def test_flow_forms():
    body = f"{BODY} flow:%s;"
    assert rule_of("alert tcp any any -> any 80", body % "to_client,not_established").flow == FlowOption("to_client", False)
    assert rule_of("alert tcp any any -> any 80", body % "established").flow == FlowOption(None, True)


def test_escapes_in_content():
    rule = rule_of("alert tcp any any -> any 80", f'{BODY} content:"a\\;b\\"c\\\\d|41|";')
    assert rule.contents[0].pattern == b'a;b"c\\dA'


def test_to_dict_with_flags_is_json():
    rule = rule_of("alert tcp any any -> any 80", f"{BODY} flags:SA;")
    assert json.loads(json.dumps(rule.to_dict()))["flags"] == {"flags": ["SYN", "ACK"], "modifier": ""}


def test_random_text_never_raises():
    rng = random.Random(7)
    alphabet = string.printable + "é\ud800|;\"\\()<>:!$[],-"
    pieces = ["alert", "tcp", "any", "->", "(", ")", "content:", '"', "|", ";", "sid:1", "msg:", "flags:", "dsize:", "\\"]
    for _ in range(3000):
        text = "".join(rng.choice(pieces) if rng.random() < 0.4 else rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        assert parse_rule("f", 1, text).status in ("valid", "invalid", "unsupported")
    for _ in range(300):
        body = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 30)))
        assert parse_rule("f", 1, f"alert tcp any any -> any 80 ({body})").status in ("valid", "invalid", "unsupported")
