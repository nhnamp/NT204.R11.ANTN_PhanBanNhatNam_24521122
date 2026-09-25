"""Read packets from a PCAP file as a stream."""

import logging
from collections.abc import Iterator
from pathlib import Path

from scapy.all import PcapReader
from scapy.error import Scapy_Exception
from scapy.packet import Packet

from ids.capture.base import PacketSource

logger = logging.getLogger(__name__)


class PcapSource(PacketSource):
    """Stream a capture file, so a large file never loads into memory."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def describe(self) -> str:
        return f"pcap:{self._path}"

    def __iter__(self) -> Iterator[Packet]:
        try:
            with PcapReader(str(self._path)) as reader:
                yield from reader
        # A corrupt capture must end the run, not the program (R2.3).
        except Scapy_Exception as exc:
            logger.warning("stopped reading %s: %s", self._path, exc)
