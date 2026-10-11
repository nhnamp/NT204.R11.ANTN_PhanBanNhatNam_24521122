"""Group packets into bidirectional flows."""

import hashlib
from dataclasses import dataclass
from typing import Callable, NamedTuple

Endpoint = tuple[str, int]
HANDSHAKE, ESTABLISHED, CLOSING, CLOSED, RESET = "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET"


@dataclass
class _Flow:
    flow_id: str
    protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: float
    last_seen: float
    application_protocol: str = "UNKNOWN"
    application_rank: int = 0
    forward_packets: int = 0
    forward_bytes: int = 0
    backward_packets: int = 0
    backward_bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str | None = None
    fin_directions: tuple[str, ...] = ()


class Step(NamedTuple):
    state: str
    fin_directions: tuple[str, ...]
    restart: bool = False


class _Packet(NamedTuple):
    state: str
    flags: list[str]
    direction: str
    fin_directions: tuple[str, ...]


def _with_fin(packet: _Packet) -> tuple[str, ...]:
    """Keep the directions of the FINs in the order of their first appearance. A repeated FIN changes nothing."""
    return packet.fin_directions if packet.direction in packet.fin_directions else (*packet.fin_directions, packet.direction)


def _both_fins_seen_and_last_came_from_the_other_side(packet: _Packet) -> bool:
    return len(packet.fin_directions) == 2 and packet.direction != packet.fin_directions[1]


_ENDED = (CLOSING, CLOSED, RESET)
# One row per rule of the transition table. The first row that matches wins, so the order is part of the table.
# The ACK rows do not exclude SYN, FIN, and RST, because the rows above them take those packets first.
_RULES: tuple[tuple[Callable[[_Packet], bool], Callable[[_Packet], Step]], ...] = (
    (lambda p: "SYN" in p.flags and "ACK" not in p.flags and p.state in _ENDED, lambda p: Step(p.state, p.fin_directions, True)),
    (lambda p: "SYN" in p.flags, lambda p: Step(p.state, p.fin_directions)),
    (lambda p: "RST" in p.flags and p.state != CLOSED, lambda p: Step(RESET, p.fin_directions)),
    (lambda p: "RST" in p.flags, lambda p: Step(p.state, p.fin_directions)),
    (lambda p: "FIN" in p.flags and p.state in (HANDSHAKE, ESTABLISHED), lambda p: Step(CLOSING, _with_fin(p))),
    (lambda p: "FIN" in p.flags and p.state == CLOSING, lambda p: Step(CLOSING, _with_fin(p))),
    (lambda p: "ACK" in p.flags and p.state == HANDSHAKE, lambda p: Step(ESTABLISHED, p.fin_directions)),
    (
        lambda p: "ACK" in p.flags and p.state == CLOSING and _both_fins_seen_and_last_came_from_the_other_side(p),
        lambda p: Step(CLOSED, p.fin_directions),
    ),
    (lambda p: True, lambda p: Step(p.state, p.fin_directions)),
)
# The first packet of a flow decides the first state. A capture can start in the middle of a connection.
_FIRST_STATES = (("SYN", HANDSHAKE), ("RST", RESET), ("FIN", CLOSING))


def first_step(flags: list[str], direction: str) -> Step:
    for flag, state in _FIRST_STATES:
        if flag in flags:
            return Step(state, (direction,) if state == CLOSING else ())
    return Step(ESTABLISHED, ())


def next_step(state: str, flags: list[str], direction: str, fin_directions: tuple[str, ...]) -> Step:
    packet = _Packet(state, flags, direction, fin_directions)
    return next(apply(packet) for matches, apply in _RULES if matches(packet))


class FlowTracker:
    def __init__(self) -> None:
        self._flows: dict[tuple, _Flow] = {}

    def update(self, view: dict) -> tuple[str, str, list[dict]]:
        """Add one packet to its flow. Return the flow id, the direction, and the flows that left the table."""
        source = (view["src_ip"], view["src_port"])
        destination = (view["dst_ip"], view["dst_port"])
        key = (view["protocol"], *sorted((source, destination)))
        flow = self._flows.get(key)
        if flow is None:
            endpoint_a = _initiator(view, source, destination)
            endpoint_b = destination if endpoint_a == source else source
            flow_id = _flow_id(view["protocol"], endpoint_a, endpoint_b, view["timestamp"])
            flow = self._flows[key] = _Flow(
                flow_id, view["protocol"], endpoint_a, endpoint_b, view["timestamp"], view["timestamp"]
            )
        forward = source == flow.endpoint_a
        direction = "forward" if forward else "backward"
        _count(flow, view, forward)
        if flow.protocol == "TCP":
            step = first_step(view["tcp_flags"], direction) if flow.state is None else next_step(
                flow.state, view["tcp_flags"], direction, flow.fin_directions
            )
            flow.state, flow.fin_directions = step.state, step.fin_directions
        return flow.flow_id, direction, []

    def flush(self) -> list[dict]:
        """Export every flow and empty the table. The sort is stable, so equal start times keep creation order."""
        flows = sorted(self._flows.values(), key=lambda flow: flow.start_time)
        self._flows.clear()
        return [_record(flow, "end_of_input") for flow in flows]


def _initiator(view: dict, source: Endpoint, destination: Endpoint) -> Endpoint:
    """Guess the client from the first packet. A SYN/ACK comes from the server."""
    flags = view["tcp_flags"]
    if view["protocol"] == "TCP" and "SYN" in flags and "ACK" in flags:
        return destination
    return source


def _flow_id(protocol: str, a: Endpoint, b: Endpoint, start_time: float) -> str:
    # The text ends with "|0" so that a later disambiguation counter changes no existing id.
    text = f"{protocol}|{a[0]}:{a[1]}|{b[0]}:{b[1]}|{start_time!r}|0"
    return f"{protocol.lower()}-{hashlib.blake2b(text.encode(), digest_size=6).hexdigest()}"


def _count(flow: _Flow, view: dict, forward: bool) -> None:
    flow.last_seen = max(flow.last_seen, view["timestamp"])
    length = view["length"] or 0
    if forward:
        flow.forward_packets += 1
        flow.forward_bytes += length
    else:
        flow.backward_packets += 1
        flow.backward_bytes += length
    flags = view["tcp_flags"]
    flow.syn_count += "SYN" in flags
    flow.ack_count += "ACK" in flags
    flow.fin_count += "FIN" in flags
    flow.rst_count += "RST" in flags
    rank = _rank(view)
    if rank > flow.application_rank:
        flow.application_protocol, flow.application_rank = view["app_protocol"], rank


def _rank(view: dict) -> int:
    """Rank a detection: from the payload 2, from the port alone 1, none 0. A later packet never lowers it."""
    method = view["detection_method"]
    if view["app_protocol"] == "UNKNOWN" or method is None:
        return 0
    return 2 if "payload" in method else 1 if method == "port" else 0


def _record(flow: _Flow, end_reason: str) -> dict:
    tcp = flow.protocol == "TCP"
    return {
        "flow_id": flow.flow_id,
        "protocol": flow.protocol,
        "application_protocol": flow.application_protocol,
        "endpoint_a": {"ip": flow.endpoint_a[0], "port": flow.endpoint_a[1]},
        "endpoint_b": {"ip": flow.endpoint_b[0], "port": flow.endpoint_b[1]},
        "start_time": flow.start_time,
        "last_seen": flow.last_seen,
        "duration": round(flow.last_seen - flow.start_time, 6),
        "packet_count": flow.forward_packets + flow.backward_packets,
        "byte_count": flow.forward_bytes + flow.backward_bytes,
        "forward_packet_count": flow.forward_packets,
        "forward_byte_count": flow.forward_bytes,
        "backward_packet_count": flow.backward_packets,
        "backward_byte_count": flow.backward_bytes,
        "syn_count": flow.syn_count if tcp else None,
        "ack_count": flow.ack_count if tcp else None,
        "fin_count": flow.fin_count if tcp else None,
        "rst_count": flow.rst_count if tcp else None,
        "state": flow.state,
        "end_reason": end_reason,
    }
