from ipaddress import IPv4Network

from ids.engine.evaluator import Evaluator
from ids.engine.model import Content, ParsedRule, PortRange, Rule
from ids.engine.repository import RuleRepository


def rule(sid, port=80, text="abc", **changes):
    fields = dict(
        sid=sid, rev=1, msg=f"rule {sid}", action="alert", protocol="tcp", src_ip=None, src_port=None,
        direction="->", dst_ip=IPv4Network("10.0.0.0/24"), dst_port=PortRange(port, port),
        contents=(Content(text, text.encode()),),
    )
    return Rule(**{**fields, **changes})


def evaluator(*rules):
    parsed = [ParsedRule("r.rules", number, "", "valid", None, item) for number, item in enumerate(rules, 1)]
    return Evaluator(RuleRepository(parsed))


def record(payload=b"xabcx", **changes):
    normalized = dict(protocol="TCP", src_ip="192.168.1.5", src_port=40000, dst_ip="10.0.0.9", dst_port=80, payload_len=len(payload))
    return {"processing_action": "keep", "payload_hex": payload.hex(), "normalized": normalized, **changes}


def test_one_record_matching_two_rules_gives_two_results():
    engine = evaluator(rule(1), rule(2, text="b"))
    matches = engine.evaluate(record(), None)
    assert [item.sid for item, _ in matches] == [1, 2]
    assert engine.rule_matches == 2


def test_counters_of_a_small_run():
    engine = evaluator(rule(1), rule(2, text="zzz"), rule(3, dst_ip=IPv4Network("10.9.0.0/24")), rule(4, protocol="ip", dst_port=None, contents=(), flow=None))
    engine.evaluate(record(), None)
    engine.evaluate({"processing_action": "drop"}, None)
    assert (engine.records_evaluated, engine.candidate_rules, engine.rule_matches) == (1, 4, 2)
    assert engine.rejected == {"header": 1, "flow": 0, "packet": 0, "content": 1}


def test_a_bad_payload_hex_falls_back_and_an_error_does_not_stop_the_run():
    engine = evaluator(rule(1))
    assert engine.evaluate(record(payload_hex="zz", payload_preview=b"abc".hex()), None)
    assert not engine.evaluate(record(payload_hex="zz", payload_preview="zz"), None)
    assert engine.engine_errors == 0 and engine.rejected["content"] == 1
    assert engine.evaluate({"processing_action": "keep", "normalized": 5}, None) == []
    assert engine.engine_errors == 1
    assert engine.evaluate(record(), None)
