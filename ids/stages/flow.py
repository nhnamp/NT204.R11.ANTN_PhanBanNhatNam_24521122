"""Group packets into bidirectional flows."""

import hashlib
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, NamedTuple

from ids.config import Config

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
    number: int = 0


class _Observation(NamedTuple):
    protocol: str
    source: Endpoint
    destination: Endpoint
    timestamp: float
    length: int
    flags: list[str]
    app_protocol: str
    rank: int


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
    def __init__(
        self,
        *,
        tcp_timeout: float = Config.tcp_timeout,
        udp_timeout: float = Config.udp_timeout,
        max_flows: int = Config.max_flows,
    ) -> None:
        self._timeouts = {"TCP": tcp_timeout, "UDP": udp_timeout}
        self._max_flows = max_flows
        # Each table holds its flows in the order of their last packet: expiry reads only the front.
        self._tables: dict[str, OrderedDict[tuple, _Flow]] = {"TCP": OrderedDict(), "UDP": OrderedDict()}
        self._now = float("-inf")
        self._created = 0
        self._pending: list[dict] = []

    def update(self, view: dict) -> tuple[str, str, list[dict]]:
        """Add one packet to its flow. Return the flow id, the direction, and the flows that left the table."""
        # Read the packet first, so a bad packet cannot change the clock or the table.
        seen = _observe(view)
        table = self._tables[seen.protocol]
        previous_now = self._now
        self._now = max(previous_now, seen.timestamp)
        self._expire()
        key = tuple(sorted((seen.source, seen.destination)))
        flow = table.get(key)
        if flow is None:
            self._make_room()
            flow = self._create(seen)
        forward = seen.source == flow.endpoint_a
        direction = "forward" if forward else "backward"
        _count(flow, seen, forward)
        if flow.protocol == "TCP":
            step = first_step(seen.flags, direction) if flow.state is None else next_step(
                flow.state, seen.flags, direction, flow.fin_directions
            )
            flow.state, flow.fin_directions = step.state, step.fin_directions
        table[key] = flow
        # A late packet keeps its flow in place: moving it would put an older flow behind a newer one.
        if seen.timestamp >= previous_now:
            table.move_to_end(key)
        return flow.flow_id, direction, self._drain()

    def flush(self) -> list[dict]:
        """Export every flow and empty the table. Equal start times keep creation order."""
        flows = sorted(
            (flow for table in self._tables.values() for flow in table.values()),
            key=lambda flow: (flow.start_time, flow.number),
        )
        records = [*self._pending, *(_record(flow, "end_of_input") for flow in flows)]
        self._pending = []
        for table in self._tables.values():
            table.clear()
        return records

    def _create(self, seen: _Observation) -> _Flow:
        endpoint_a = _initiator(seen)
        endpoint_b = seen.destination if endpoint_a == seen.source else seen.source
        flow_id = _flow_id(seen.protocol, endpoint_a, endpoint_b, seen.timestamp)
        self._created += 1
        return _Flow(
            flow_id, seen.protocol, endpoint_a, endpoint_b, seen.timestamp, seen.timestamp, number=self._created
        )

    def _expire(self) -> None:
        """Export the flows that were idle for longer than their timeout."""
        expired: list[tuple[tuple, _Flow]] = []
        for protocol, table in self._tables.items():
            for key, flow in table.items():
                if self._now - flow.last_seen <= self._timeouts[protocol]:
                    break
                expired.append((key, flow))
        expired.sort(key=lambda item: (item[1].last_seen, item[1].number))
        self._release(expired, "idle_timeout")

    def _make_room(self) -> None:
        """Export the flow with the smallest last packet time when a new flow would pass the limit."""
        if sum(len(table) for table in self._tables.values()) < self._max_flows:
            return
        # Only the front of each table is read: it is the oldest flow unless a late packet changed the order.
        fronts = [next(iter(table.items())) for table in self._tables.values() if table]
        self._release([min(fronts, key=lambda item: (item[1].last_seen, item[1].number))], "evicted")

    def _release(self, flows: list[tuple[tuple, _Flow]], end_reason: str) -> None:
        # The records exist before the flows leave the table, so a failure here loses no flow.
        records = [_record(flow, end_reason) for _, flow in flows]
        self._pending.extend(records)
        for key, flow in flows:
            del self._tables[flow.protocol][key]

    def _drain(self) -> list[dict]:
        exported, self._pending = self._pending, []
        return exported


def _observe(view: dict) -> _Observation:
    return _Observation(
        view["protocol"],
        (view["src_ip"], view["src_port"]),
        (view["dst_ip"], view["dst_port"]),
        view["timestamp"],
        view["length"] or 0,
        view["tcp_flags"],
        view["app_protocol"],
        _rank(view),
    )


def _initiator(seen: _Observation) -> Endpoint:
    """Guess the client from the first packet. A SYN/ACK comes from the server."""
    if seen.protocol == "TCP" and "SYN" in seen.flags and "ACK" in seen.flags:
        return seen.destination
    return seen.source


def _flow_id(protocol: str, a: Endpoint, b: Endpoint, start_time: float) -> str:
    # The text ends with "|0" so that a later disambiguation counter changes no existing id.
    text = f"{protocol}|{a[0]}:{a[1]}|{b[0]}:{b[1]}|{start_time!r}|0"
    return f"{protocol.lower()}-{hashlib.blake2b(text.encode(), digest_size=6).hexdigest()}"


def _count(flow: _Flow, seen: _Observation, forward: bool) -> None:
    flow.last_seen = max(flow.last_seen, seen.timestamp)
    if forward:
        flow.forward_packets += 1
        flow.forward_bytes += seen.length
    else:
        flow.backward_packets += 1
        flow.backward_bytes += seen.length
    flow.syn_count += "SYN" in seen.flags
    flow.ack_count += "ACK" in seen.flags
    flow.fin_count += "FIN" in seen.flags
    flow.rst_count += "RST" in seen.flags
    if seen.rank > flow.application_rank:
        flow.application_protocol, flow.application_rank = seen.app_protocol, seen.rank


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
