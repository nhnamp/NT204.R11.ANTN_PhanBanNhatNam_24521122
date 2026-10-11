"""Group packets into bidirectional flows."""

import hashlib
from dataclasses import dataclass

Endpoint = tuple[str, int]


@dataclass
class _Flow:
    flow_id: str
    endpoint_a: Endpoint


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
            flow = self._flows[key] = _Flow(flow_id, endpoint_a)
        return flow.flow_id, "forward" if source == flow.endpoint_a else "backward", []


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
