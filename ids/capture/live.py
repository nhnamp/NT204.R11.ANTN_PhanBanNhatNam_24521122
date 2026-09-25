"""Capture packets from a live network interface."""

import threading
from collections.abc import Iterator
from queue import SimpleQueue

from scapy.error import Scapy_Exception
from scapy.packet import Packet
from scapy.sendrecv import sniff

from ids.capture.base import PacketSource


class LiveSource(PacketSource):
    """Hand live packets to the shared loop through a queue."""

    def __init__(self, interface: str, count: int | None = None) -> None:
        self._interface = interface
        self._count = count

    def describe(self) -> str:
        return f"live:{self._interface}"

    def __iter__(self) -> Iterator[Packet]:
        packets: SimpleQueue[Packet | None] = SimpleQueue()
        failures: list[Exception] = []
        stop = threading.Event()

        def collect(packet: Packet) -> None:
            packets.put(packet)

        def capture() -> None:
            try:
                sniff(
                    iface=self._interface,
                    store=False,
                    prn=collect,
                    count=self._count,
                    stop_filter=lambda _: stop.is_set(),
                )
            except Scapy_Exception as exc:
                # Scapy raises its own exception type when it cannot open /dev/bpf without root.
                if "Permission denied" in str(exc):
                    failures.append(PermissionError(str(exc)))
                else:
                    failures.append(OSError(str(exc)))
            # A thread cannot raise into its caller, so pass the failure to the consumer.
            except Exception as exc:
                failures.append(exc)
            finally:
                # The consumer blocks on the queue, so it must always get the sentinel.
                packets.put(None)

        worker = threading.Thread(target=capture, daemon=True)
        worker.start()
        try:
            while True:
                packet = packets.get()
                if packet is None:
                    break
                yield packet
        finally:
            stop.set()
            worker.join(timeout=1.0)
        if failures:
            raise failures[0]
