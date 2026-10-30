"""Build the rule match record. The generator never prints."""

from ids.engine.model import MatchResult, Rule, RuleMatch
from ids.stages.flow import FlowContext


def build_rule_match(rule: Rule, record: dict, flow: FlowContext | None, result: MatchResult) -> RuleMatch:
    normalized = record["normalized"]
    return RuleMatch(
        timestamp=normalized["timestamp"],
        timestamp_iso=normalized["timestamp_iso"],
        sid=rule.sid,
        rev=rule.rev,
        msg=rule.msg,
        classtype=rule.classtype,
        priority=rule.priority,
        protocol=normalized["protocol"],
        src_ip=normalized["src_ip"],
        src_port=normalized["src_port"],
        dst_ip=normalized["dst_ip"],
        dst_port=normalized["dst_port"],
        application_protocol=normalized["app_protocol"],
        flow_id=flow.flow_id if flow else None,
        direction=flow.direction if flow else None,
        flow_state=flow.state if flow else None,
        packet_id=record.get("packet_id"),
        source=record.get("source"),
        matched=result.items,
    )
