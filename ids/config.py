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
