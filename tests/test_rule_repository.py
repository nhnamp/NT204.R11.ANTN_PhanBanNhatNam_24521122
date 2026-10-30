from ids.engine.parser import parse_rule
from ids.engine.repository import RuleRepository

RULES = {
    1: "alert ip any any -> any any",
    2: "alert tcp any any -> any 80",
    3: "alert udp any any -> any 53",
    4: "alert tcp any any -> any any",
    5: "alert udp any any -> any 1024:",
}


def parsed(rules):
    return [parse_rule("r.rules", number, f'{header} (msg:"x"; sid:{sid};)') for number, (sid, header) in enumerate(rules.items(), 1)]


def record(protocol, src_port, dst_port):
    return {"normalized": {"protocol": protocol, "src_port": src_port, "dst_port": dst_port}}


def sids(repository, rec):
    return [rule.sid for rule in repository.candidates(rec)]


def test_candidates_by_protocol_and_port():
    repository = RuleRepository(parsed(RULES), [])
    assert sids(repository, record("TCP", 51000, 80)) == [1, 2, 4]
    assert sids(repository, record("UDP", 51000, 53)) == [1, 3, 5]
    assert sids(repository, record("TCP", 51000, 22)) == [1, 4]
    assert sids(repository, record("ICMP", None, None)) == []


def test_bidirectional_rule_is_found_by_either_port():
    repository = RuleRepository(parsed({1: "alert tcp any 22 <> any 80", 2: "alert tcp any any -> any 443"}))
    assert sids(repository, record("TCP", 80, 51000)) == [1]
    assert sids(repository, record("TCP", 51000, 22)) == [1]
    assert sids(repository, record("TCP", 51000, 443)) == [2]


def test_duplicate_and_disabled_sids_are_rejected_with_a_reason():
    entries = parsed({1: "alert tcp any any -> any 80", 2: "alert tcp any any -> any 81"})
    entries.append(parse_rule("r.rules", 9, 'alert tcp any any -> any 82 (msg:"y"; sid:1;)'))
    repository = RuleRepository(entries, [2])
    assert len(repository) == 1 and sids(repository, record("TCP", 1, 80)) == [1]
    disabled, duplicate = repository.rejected
    assert (duplicate.status, duplicate.reason, duplicate.rule, duplicate.line) == ("invalid", "duplicate sid 1", None, 9)
    assert (disabled.status, disabled.rule.sid) == ("disabled", 2)
    assert sids(repository, record("TCP", 1, 81)) == []
