"""Parse the IPv4 header into the network part of an event.

Byte offsets of every parsed field:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------+-------+---------------+-------------------------------+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-------+-------+---------------+-------------------------------+
   |         Identification        |Flags|      Fragment Offset    |
   +---------------+---------------+-------------------------------+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +---------------+---------------+-------------------------------+
   |                       Source Address                          |
   +---------------------------------------------------------------+
   |                    Destination Address                        |
   +---------------------------------------------------------------+
   |                    Options                    |    Padding    |
   +-----------------------------------------------+---------------+

   version            0   4 bits     dscp              1   6 bits (high)
   ihl                0   4 bits     total_len         2   2 bytes
   identification     4   2 bytes    flags             6   3 bits
   fragment offset    6   13 bits    ttl               8   1 byte
   protocol           9   1 byte     header checksum  10   2 bytes
   source address    12   4 bytes    destination      16   4 bytes
   options           20   0 to 40 bytes
"""

from scapy.layers.inet import IP
from scapy.packet import Packet

from ids.events import NetworkInfo, ParseError

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
FLAG_NAMES = ("DF", "MF")


def parse_ipv4(packet: Packet) -> tuple[NetworkInfo | None, list[ParseError]]:
    layer = packet.getlayer(IP)
    if layer is None:
        return None, []
    header_len = (layer.ihl or 0) * 4
    total_len = layer.len or 0
    errors: list[ParseError] = []
    # The fixed header is 20 bytes (RFC 791 section 3.1). A bad length keeps the addresses,
    # because the source of a malformed packet is what an IDS needs most.
    if header_len < 20:
        errors.append(_malformed("IPv4 header is shorter than 20 bytes"))
    elif total_len < header_len:
        errors.append(_malformed("IPv4 total length is smaller than the header"))
    info = NetworkInfo(
        protocol="IPv4",
        src_ip=str(layer.src),
        dst_ip=str(layer.dst),
        version=layer.version,
        header_len=header_len,
        dscp=layer.tos >> 2,
        total_len=total_len,
        identification=layer.id,
        flags=[name for name in FLAG_NAMES if name in layer.flags],
        frag_offset=layer.frag * 8,
        ttl=layer.ttl,
        proto_number=layer.proto,
        proto_name=PROTOCOL_NAMES.get(layer.proto, str(layer.proto)),
        checksum=layer.chksum,
        has_options=bool(layer.options),
    )
    return info, errors


def _malformed(message: str) -> ParseError:
    return ParseError(stage="network", type="malformed", message=message)
