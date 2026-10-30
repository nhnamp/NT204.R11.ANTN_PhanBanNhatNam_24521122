"""Match one rule against one packet record. The stages run in order, and the first failure stops."""

from ipaddress import AddressValueError, IPv4Address, IPv4Network

from ids.engine.model import FlowOption, MatchedItem, MatchResult, PortRange, Rule
from ids.stages.flow import CLOSING, ESTABLISHED, FlowContext

_DIRECTIONS = {"to_server": "forward", "to_client": "backward"}


def match(rule: Rule, record: dict, payload: bytes, flow: FlowContext | None) -> MatchResult:
    normalized = record["normalized"]
    if not _header_matches(rule, normalized):
        return MatchResult(rule.sid, False, "header")
    items = []
    if rule.flow is not None:
        if flow is None or not _flow_matches(rule.flow, flow):
            return MatchResult(rule.sid, False, "flow")
        items.append(MatchedItem("flow", _flow_text(rule.flow)))
    return MatchResult(rule.sid, True, items=tuple(items))


def _header_matches(rule: Rule, normalized: dict) -> bool:
    protocol = (normalized.get("protocol") or "").upper()
    if rule.protocol != "ip" and rule.protocol.upper() != protocol:
        return False
    if rule.protocol == "ip" and protocol not in ("TCP", "UDP"):
        return False
    src = (normalized.get("src_ip"), normalized.get("src_port"))
    dst = (normalized.get("dst_ip"), normalized.get("dst_port"))
    if _endpoints_match(rule.src_ip, rule.src_port, src) and _endpoints_match(rule.dst_ip, rule.dst_port, dst):
        return True
    # A bidirectional rule also matches the reversed orientation.
    return rule.direction == "<>" and _endpoints_match(rule.src_ip, rule.src_port, dst) and _endpoints_match(
        rule.dst_ip, rule.dst_port, src
    )


def _endpoints_match(network: IPv4Network | None, ports: PortRange | None, endpoint: tuple) -> bool:
    address, port = endpoint
    if network is not None:
        try:
            if IPv4Address(address) not in network:
                return False
        except (AddressValueError, ValueError):
            return False
    if ports is not None:
        if not isinstance(port, int) or not ports.low <= port <= ports.high:
            return False
    return True


def _flow_matches(option: FlowOption, flow: FlowContext) -> bool:
    if option.direction is not None and flow.direction != _DIRECTIONS[option.direction]:
        return False
    if option.established is not None and _is_established(flow) != option.established:
        return False
    return True


def _is_established(flow: FlowContext) -> bool:
    if flow.state is None:
        return flow.forward_packets > 0 and flow.backward_packets > 0
    return flow.state in (ESTABLISHED, CLOSING)


def _flow_text(option: FlowOption) -> str:
    parts = [option.direction] if option.direction else []
    if option.established is not None:
        parts.append("established" if option.established else "not_established")
    return ",".join(parts)
