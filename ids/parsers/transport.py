"""Parse the TCP and UDP headers into the transport part of an event.

TCP header (RFC 793 section 3.1), with byte offsets:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------------------------------+-------------------------------+
   |          Source Port          |       Destination Port        |
   +-------------------------------+-------------------------------+
   |                        Sequence Number                        |
   +---------------------------------------------------------------+
   |                    Acknowledgment Number                      |
   +-------+-------+-+-+-+-+-+-+-+-+-------------------------------+
   |  Data |       |C|E|U|A|P|R|S|F|                               |
   | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
   |       |       |R|E|G|K|H|T|N|N|                               |
   +-------+-------+-+-+-+-+-+-+-+-+-------------------------------+
   |           Checksum            |         Urgent Pointer        |
   +-------------------------------+-------------------------------+
   |                    Options                    |    Padding    |
   +-----------------------------------------------+---------------+

   source port        0   2 bytes    sequence number   4   4 bytes
   destination port   2   2 bytes    acknowledgment    8   4 bytes
   data offset       12   4 bits     flags            13   1 byte
   window            14   2 bytes    checksum         16   2 bytes
   urgent pointer    18   2 bytes    options          20   0 to 40 bytes

UDP header (RFC 768), with byte offsets:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------------------------------+-------------------------------+
   |          Source Port          |       Destination Port        |
   +-------------------------------+-------------------------------+
   |            Length             |           Checksum            |
   +-------------------------------+-------------------------------+

   source port        0   2 bytes    length             4   2 bytes
   destination port   2   2 bytes    checksum           6   2 bytes
"""

from scapy.layers.inet import TCP
from scapy.packet import Packet

from ids.events import NetworkInfo, ParseError, TransportInfo

TCP_FLAGS = (
    ("FIN", 0x01),
    ("SYN", 0x02),
    ("RST", 0x04),
    ("PSH", 0x08),
    ("ACK", 0x10),
    ("URG", 0x20),
    ("ECE", 0x40),
    ("CWR", 0x80),
)

NAMED_OPTIONS = {"MSS", "WScale", "SAckOK", "Timestamp", "NOP"}
TCP_PROTOCOL = 6


def parse_transport(
    packet: Packet, network: NetworkInfo
) -> tuple[TransportInfo | None, bytes, list[ParseError]]:
    layer = packet.getlayer(TCP)
    if layer is None:
        if network.proto_number == TCP_PROTOCOL:
            # Scapy turns a TCP header shorter than 20 bytes into Raw, so no TCP layer exists.
            error = ParseError(stage="transport", type="truncated", message="TCP header is cut")
            return None, b"", [error]
        return None, b"", []
    return _parse_tcp(layer, network)


def _parse_tcp(layer: TCP, network: NetworkInfo) -> tuple[TransportInfo, bytes, list[ParseError]]:
    raw_flags = int(layer.flags)
    flags = [name for name, bit in TCP_FLAGS if raw_flags & bit]
    captured = bytes(layer.payload)
    declared = max(network.total_len - network.header_len - layer.dataofs * 4, 0)
    # The IP length excludes Ethernet padding, which pads a short frame up to 60 bytes.
    payload = captured[:declared]
    errors: list[ParseError] = []
    if declared > len(captured):
        errors.append(
            ParseError(
                stage="transport",
                type="truncated",
                message=f"declared {declared} payload bytes, found {len(captured)}",
            )
        )
    info = TransportInfo(
        protocol="TCP",
        src_port=layer.sport,
        dst_port=layer.dport,
        payload_len=len(payload),
        checksum=layer.chksum,
        seq=layer.seq,
        ack=layer.ack,
        data_offset=layer.dataofs,
        flags=flags,
        flags_raw=raw_flags,
        flags_str=str(layer.flags),
        window=layer.window,
        urgent_ptr=layer.urgptr,
        options=_options(layer.options),
        handshake=_handshake(flags, len(payload)),
    )
    return info, payload, errors


def _options(options: list) -> list[list]:
    parsed = []
    for name, value in options:
        if name not in NAMED_OPTIONS:
            parsed.append([name])
        elif isinstance(value, bytes):
            parsed.append([name, value.hex()])
        elif isinstance(value, tuple):
            parsed.append([name, list(value)])
        else:
            parsed.append([name, value])
    return parsed


def _handshake(flags: list[str], payload_len: int) -> str | None:
    names = set(flags)
    if names == {"SYN"}:
        return "SYN"
    if names == {"SYN", "ACK"}:
        return "SYN/ACK"
    if "ACK" in names and not names & {"SYN", "FIN", "RST"} and payload_len == 0:
        return "ACK"
    return None
