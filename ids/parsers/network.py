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

from ids.events import NetworkInfo

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
FLAG_NAMES = ("DF", "MF")


def parse_ipv4(packet: Packet) -> NetworkInfo | None:
    layer = packet.getlayer(IP)
    if layer is None:
        return None
    return NetworkInfo(
        protocol="IPv4",
        src_ip=str(layer.src),
        dst_ip=str(layer.dst),
        version=layer.version,
        header_len=layer.ihl * 4,
        dscp=layer.tos >> 2,
        total_len=layer.len,
        identification=layer.id,
        flags=[name for name in FLAG_NAMES if name in layer.flags],
        frag_offset=layer.frag * 8,
        ttl=layer.ttl,
        proto_number=layer.proto,
        proto_name=PROTOCOL_NAMES.get(layer.proto, str(layer.proto)),
        checksum=layer.chksum,
        has_options=bool(layer.options),
    )
