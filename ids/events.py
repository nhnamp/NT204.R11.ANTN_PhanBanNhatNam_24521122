"""The normalized event contract, and its conversion to JSON-compatible values."""

from dataclasses import dataclass, field, fields, is_dataclass
from typing import Literal

AppProtocol = Literal["HTTP", "DNS", "SMTP", "UNKNOWN"]
Status = Literal["ok", "partial", "unsupported", "malformed"]

PAYLOAD_PREVIEW_BYTES = 64


def preview_payload(payload: bytes) -> str:
    """Keep the event small, and keep enough payload to explain detection."""
    return payload[:PAYLOAD_PREVIEW_BYTES].hex()


@dataclass
class ParseError:
    """One stage failure, kept in the event so a bad packet never stops the loop."""

    stage: str
    type: str
    message: str


@dataclass
class NetworkInfo:
    """IPv4 header fields, written by the network parser stage."""

    protocol: str
    src_ip: str
    dst_ip: str
    version: int
    header_len: int
    dscp: int
    total_len: int
    identification: int
    flags: list[str]
    frag_offset: int
    ttl: int
    proto_number: int
    proto_name: str
    checksum: int | None
    has_options: bool


@dataclass
class TransportInfo:
    """TCP or UDP header fields, written by the transport parser stage."""

    protocol: Literal["TCP", "UDP"]
    src_port: int
    dst_port: int
    payload_len: int
    checksum: int | None = None
    length: int | None = None
    seq: int | None = None
    ack: int | None = None
    data_offset: int | None = None
    flags: list[str] = field(default_factory=list)
    flags_raw: int | None = None
    flags_str: str | None = None
    window: int | None = None
    urgent_ptr: int | None = None
    options: list[list[str | int | None]] = field(default_factory=list)
    handshake: Literal["SYN", "SYN/ACK", "ACK"] | None = None


@dataclass
class Detection:
    """How the application protocol was decided."""

    protocol: AppProtocol
    method: Literal["payload", "port", "port+payload", "none"]
    confidence: Literal["high", "low"]
    rule: str


@dataclass
class AppInfo:
    """Base for the protocol-specific application types, added one per protocol."""


@dataclass
class Event:
    """One captured packet after every parser stage."""

    packet_id: int
    timestamp: float
    timestamp_iso: str
    source: str
    length: int
    link_type: str
    network: NetworkInfo | None
    transport: TransportInfo | None
    app_protocol: AppProtocol
    detection: Detection | None
    application: AppInfo | None
    payload_len: int
    payload_preview: str
    status: Status
    errors: list[ParseError]

    def to_dict(self) -> dict[str, object]:
        """Return JSON-compatible values for the writer."""
        return _jsonable(self, "event")


def _jsonable(value: object, path: str) -> object:
    """Reject a value that json.dumps cannot serialize, and name its field path."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        return [_jsonable(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        return {str(key): _jsonable(item, f"{path}.{key}") for key, item in value.items()}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _jsonable(getattr(value, item.name), f"{path}.{item.name}")
            for item in fields(value)
        }
    raise TypeError(f"{path} holds {type(value).__name__}, which is not JSON-compatible")
