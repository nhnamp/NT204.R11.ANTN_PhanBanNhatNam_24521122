"""Match one rule against one packet record. The stages run in order, and the first failure stops."""

from ipaddress import AddressValueError, IPv4Address, IPv4Network

from ids.engine.model import MatchResult, PortRange, Rule
from ids.stages.flow import FlowContext


def match(rule: Rule, record: dict, payload: bytes, flow: FlowContext | None) -> MatchResult:
    normalized = record["normalized"]
    if not _header_matches(rule, normalized):
        return MatchResult(rule.sid, False, "header")
    return MatchResult(rule.sid, True)


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
