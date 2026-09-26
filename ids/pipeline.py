from datetime import datetime, timezone
from typing import Any

from ids.config import Config
from ids.events import Event, ParseError, Status
from ids.parsers.network import parse_ipv4

LINK_TYPES = {
    "Ether": "Ethernet",
    "CookedLinux": "LinuxSLL",
    "IP": "RawIP",
}


class Pipeline:
    def __init__(self, config: Config, source: str) -> None:
        self._config = config
        self._source = source
        self._packet_id = 0

    def process(self, packet: Any) -> Event | None:
        """Build one event per packet, and never raise (ERR-1)."""
        self._packet_id += 1
        try:
            return self._build_event(self._packet_id, packet)
        # The guard is deliberately broad: one bad packet must not end the capture loop.
        except Exception as exc:
            return self._malformed_event(self._packet_id, exc)

    def _build_event(self, packet_id: int, packet: Any) -> Event:
        """Fill the event envelope. Parser stages replace the constants later."""
        timestamp = float(packet.time)
        network = parse_ipv4(packet)
        errors: list[ParseError] = []
        status: Status = "unsupported"
        if network is not None and network.frag_offset > 0:
            status = "partial"
            errors.append(
                ParseError(stage="network", type="fragment", message="non-first fragment")
            )
        return Event(
            packet_id=packet_id,
            timestamp=timestamp,
            timestamp_iso=_iso(timestamp),
            source=self._source,
            length=len(packet),
            link_type=_link_type(packet),
            network=network,
            transport=None,
            app_protocol="UNKNOWN",
            detection=None,
            application=None,
            payload_len=0,
            payload_preview="",
            status=status,
            errors=errors,
        )

    def _malformed_event(self, packet_id: int, exc: Exception) -> Event:
        """Keep the failed packet in the output, so the corpus stays visible."""
        return Event(
            packet_id=packet_id,
            timestamp=0.0,
            timestamp_iso=_iso(0.0),
            source=self._source,
            length=0,
            link_type="",
            network=None,
            transport=None,
            app_protocol="UNKNOWN",
            detection=None,
            application=None,
            payload_len=0,
            payload_preview="",
            status="malformed",
            errors=[ParseError(stage="pipeline", type=type(exc).__name__, message=str(exc))],
        )


def _link_type(packet: Any) -> str:
    class_name = type(packet).__name__
    return LINK_TYPES.get(class_name, class_name)


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
