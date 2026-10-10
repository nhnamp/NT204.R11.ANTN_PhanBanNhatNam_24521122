"""Run settings shared by the capture, pipeline, and output stages."""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Config:
    """One parsed command line, passed down the pipeline unchanged."""

    interface: str | None
    pcap: str | None
    output: str
    unknown: Literal["keep", "drop"]
    count: int | None
    events: str | None = None
    payload: Literal["preview", "full"] = "full"
    payload_limit: int = 4096
    tcp_timeout: float = 120.0
    udp_timeout: float = 30.0
    max_flows: int = 100_000
    flows_output: str = "flows.jsonl"
