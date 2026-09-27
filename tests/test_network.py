from pathlib import Path

import pytest
from scapy.all import ARP, Ether, IP, IPv6, PcapReader, Raw, TCP
from scapy.layers.inet import IPOption
from scapy.packet import Packet

from ids.events import NetworkInfo
from ids.parsers.network import parse_ipv4

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _dissect(packet: Packet) -> Packet:
    """Read the frame back, because Scapy fills ihl and the checksum only on build."""
    return Ether(bytes(packet))


def test_first_basic_pcap_packet_fills_every_field(basic_pcap: Path) -> None:
    """Expected values are frame 1 of basic.pcap, as Wireshark shows them.

    Wireshark shows the same IPv4 fields: DSCP EF (46), Don't fragment, and checksum 0x2615.
    """
    with PcapReader(str(basic_pcap)) as reader:
        first = next(iter(reader))

    assert parse_ipv4(first) == (NetworkInfo(
        protocol="IPv4",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        version=4,
        header_len=20,
        dscp=46,
        total_len=40,
        identification=1,
        flags=["DF"],
        frag_offset=0,
        ttl=64,
        proto_number=6,
        proto_name="TCP",
        checksum=0x2615,
        has_options=False,
    ), [])


def test_options_are_reported_in_the_header_length() -> None:
    crafted = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(options=[IPOption(b"\x01")]) / TCP()

    info, _ = parse_ipv4(_dissect(crafted))

    assert info is not None
    assert info.has_options is True
    assert info.header_len == 24


@pytest.mark.parametrize(("proto", "expected"), [(1, "ICMP"), (6, "TCP"), (17, "UDP"), (253, "253")])
def test_protocol_names_cover_the_known_set(proto: int, expected: str) -> None:
    crafted = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(proto=proto) / Raw(b"")

    info, _ = parse_ipv4(_dissect(crafted))

    assert info is not None
    assert info.proto_name == expected


@pytest.mark.parametrize(
    "packet",
    [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) / ARP(),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IPv6(),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) / Raw(b"payload"),
    ],
)
def test_non_ipv4_packets_have_no_network_info(packet: Packet) -> None:
    assert parse_ipv4(packet) == (None, [])


@pytest.mark.parametrize(
    ("offset", "value", "message"),
    [
        (14, b"\x43", "IPv4 header is shorter than 20 bytes"),
        (16, (10).to_bytes(2, "big"), "IPv4 total length is smaller than the header"),
    ],
)
def test_a_bad_length_is_malformed_and_keeps_the_addresses(
    offset: int, value: bytes, message: str
) -> None:
    raw = bytearray(bytes(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    raw[offset : offset + len(value)] = value

    info, errors = parse_ipv4(Ether(bytes(raw)))

    assert info is not None
    assert (info.src_ip, info.dst_ip) == ("10.0.0.1", "10.0.0.2")
    assert [(error.stage, error.type, error.message) for error in errors] == [("network", "malformed", message)]
