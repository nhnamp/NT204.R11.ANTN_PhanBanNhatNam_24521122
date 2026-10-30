"""Match one rule against one packet record. The stages run in order, and the first failure stops."""

from ipaddress import AddressValueError, IPv4Address, IPv4Network

from ids.engine.model import Content, DsizeOption, FlagsOption, FlowOption, MatchedItem, MatchResult, PortRange, Rule
from ids.stages.flow import CLOSING, ESTABLISHED, FlowContext
from ids.stages.preprocessor import TCP_FLAGS

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
    if rule.flags is not None:
        if not _flags_match(rule.flags, normalized):
            return MatchResult(rule.sid, False, "packet")
        items.append(MatchedItem("flags", _flags_text(rule.flags)))
    if rule.dsize is not None:
        if not _dsize_matches(rule.dsize, normalized.get("payload_len")):
            return MatchResult(rule.sid, False, "packet")
        items.append(MatchedItem("dsize", _dsize_text(rule.dsize)))
    positions = _content_positions(rule.contents, payload)
    if positions is None:
        return MatchResult(rule.sid, False, "content")
    items.extend(MatchedItem("content", content.text, position) for content, position in zip(rule.contents, positions))
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


def _flags_match(option: FlagsOption, normalized: dict) -> bool:
    if (normalized.get("protocol") or "").upper() != "TCP":
        return False
    present = set(normalized.get("tcp_flags") or ())
    if option.modifier == "+":
        return option.flags <= present
    if option.modifier == "*":
        return bool(option.flags & present)
    if option.modifier == "!":
        return not option.flags & present
    return option.flags == present


def _flags_text(option: FlagsOption) -> str:
    return option.modifier + (",".join(sorted(option.flags, key=TCP_FLAGS.index)) or "0")


def _dsize_matches(option: DsizeOption, size: int | None) -> bool:
    if size is None:
        return False
    if option.operator == ">":
        return size > option.value
    if option.operator == "<":
        return size < option.value
    if option.operator == "<>":
        return option.value <= size <= (option.upper if option.upper is not None else option.value)
    return size == option.value


def _dsize_text(option: DsizeOption) -> str:
    if option.operator == "<>":
        return f"{option.value}<>{option.upper}"
    return f"{'' if option.operator == '=' else option.operator}{option.value}"


def _content_positions(contents: tuple[Content, ...], payload: bytes) -> list[int] | None:
    """Return the start of every content, or `None`. Each content tries all its occurrences, so a later one can still fit."""
    if not contents:
        return []
    return _place(contents, 0, 0, payload, payload.lower())


def _place(contents: tuple[Content, ...], index: int, previous_end: int, payload: bytes, lowered: bytes) -> list[int] | None:
    if index == len(contents):
        return []
    content = contents[index]
    buffer, pattern = (lowered, content.pattern.lower()) if content.nocase else (payload, content.pattern)
    start, end = _region(content, previous_end, len(buffer))
    position = buffer.find(pattern, start, end)
    while position != -1:
        rest = _place(contents, index + 1, position + len(pattern), payload, lowered)
        if rest is not None:
            return [position, *rest]
        position = buffer.find(pattern, position + 1, end)
    return None


def _region(content: Content, previous_end: int, size: int) -> tuple[int, int]:
    """Return the search window. `within` and `depth` limit the bytes that the whole pattern must fit in."""
    if content.distance is not None or content.within is not None:
        start = max(previous_end + (content.distance or 0), 0)
        length = content.within
    else:
        start = content.offset or 0
        length = content.depth
    end = size if length is None else min(start + length, size)
    return start, end
