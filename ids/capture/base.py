"""PacketSource interface shared by the PCAP source and the live source."""

from abc import ABC, abstractmethod
from collections.abc import Iterator

from scapy.packet import Packet


class PacketSource(ABC):
    """Feed captured packets to the pipeline, one at a time."""

    @abstractmethod
    def __iter__(self) -> Iterator[Packet]:
        """Yield one packet per captured unit."""

    @abstractmethod
    def describe(self) -> str:
        """Name the source the way the event schema expects it."""
