import pytest
from scapy.all import ICMP, Ether, IP, Raw, TCP, UDP
from scapy.layers.vxlan import VXLAN
from scapy.packet import Packet

from ids.events import TransportInfo
from ids.parsers.network import parse_ipv4
from ids.parsers.transport import parse_transport

CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def _parse(crafted: Packet) -> tuple[TransportInfo | None, bytes, list]:
    """Dissect the frame first, because Scapy fills the header only on build."""
    packet = Ether(bytes(crafted))
    return parse_transport(packet, parse_ipv4(packet))


def _tcp(flags: str, payload: bytes = b"") -> Packet:
    frame = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags=flags)
    )
    return frame / Raw(payload) if payload else frame


def _udp(payload: bytes = b"") -> Packet:
    frame = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=53)
    )
    return frame / Raw(payload) if payload else frame


def _padded(crafted: Packet) -> Packet:
    """Pad the frame to the 60-byte Ethernet minimum, as a real network does."""
    raw = bytes(crafted)
    return Ether(raw + b"\x00" * (60 - len(raw)))


def test_tcp_fields_are_parsed() -> None:
    crafted = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(
            sport=40000,
            dport=80,
            seq=1000,
            ack=2000,
            flags="SA",
            window=65535,
            chksum=0x1234,
            urgptr=0,
            options=[
                ("MSS", 1460),
                ("WScale", 7),
                ("SAckOK", b""),
                ("Timestamp", (123, 456)),
                ("NOP", None),
            ],
        )
    )

    info, payload, errors = _parse(crafted)

    assert (payload, errors) == (b"", [])
    assert info == TransportInfo(
        protocol="TCP",
        src_port=40000,
        dst_port=80,
        payload_len=0,
        checksum=0x1234,
        seq=1000,
        ack=2000,
        data_offset=10,
        flags=["SYN", "ACK"],
        flags_raw=18,
        flags_str="SA",
        window=65535,
        urgent_ptr=0,
        options=[
            ["MSS", 1460],
            ["WScale", 7],
            ["SAckOK", ""],
            ["Timestamp", [123, 456]],
            ["NOP", None],
        ],
        handshake="SYN/ACK",
    )


@pytest.mark.parametrize(
    ("flags", "payload", "expected"),
    [
        ("S", b"", "SYN"),
        ("SA", b"", "SYN/ACK"),
        ("A", b"", "ACK"),
        ("PA", b"", "ACK"),
        ("PA", b"x", None),
        ("FA", b"", None),
        ("RA", b"", None),
        ("FSA", b"", None),
    ],
)
def test_handshake_steps(flags: str, payload: bytes, expected: str | None) -> None:
    info, _, _ = _parse(_tcp(flags, payload))

    assert info is not None
    assert info.handshake == expected


def test_ethernet_padding_is_not_payload() -> None:
    packet = _padded(_tcp("A"))
    info, payload, errors = parse_transport(packet, parse_ipv4(packet))

    assert info is not None
    assert (payload, errors, info.handshake) == (b"", [], "ACK")


def test_cut_tcp_header_is_reported() -> None:
    raw = bytes(_tcp("S"))
    packet = Ether(raw[: 14 + 20 + 8])
    info, payload, errors = parse_transport(packet, parse_ipv4(packet))

    assert (info, payload) == (None, b"")
    assert [(error.stage, error.type) for error in errors] == [("transport", "truncated")]


def test_declared_length_beyond_the_frame_reports_truncation() -> None:
    body = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    raw = bytes(_tcp("PA", body))

    packet = Ether(raw[: len(raw) - 10])
    info, payload, errors = parse_transport(packet, parse_ipv4(packet))

    assert info is not None
    assert len(payload) == len(body) - 10
    assert [(error.stage, error.type) for error in errors] == [("transport", "truncated")]


def test_udp_fields_are_parsed() -> None:
    crafted = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=53, chksum=0x1234)
        / Raw(b"udp-payload!")
    )

    info, payload, errors = _parse(crafted)

    assert (payload, errors) == (b"udp-payload!", [])
    assert info == TransportInfo(
        protocol="UDP",
        src_port=40000,
        dst_port=53,
        payload_len=12,
        length=20,
        checksum=0x1234,
    )


def test_udp_declared_length_beyond_the_frame_reports_truncation() -> None:
    raw = bytes(_udp(b"udp-payload!"))

    packet = Ether(raw[: len(raw) - 4])
    info, payload, errors = parse_transport(packet, parse_ipv4(packet))

    assert info is not None
    assert len(payload) == 8
    assert [(error.stage, error.type) for error in errors] == [("transport", "truncated")]


def test_other_l4_protocols_have_no_transport_info() -> None:
    crafted = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(proto=1) / ICMP()

    assert _parse(crafted) == (None, b"", [])


def test_tunnel_reports_the_outer_transport() -> None:
    crafted = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=50000, dport=4789)
        / VXLAN(vni=1)
        / Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="192.168.0.1", dst="192.168.0.2")
        / TCP(sport=1234, dport=80)
    )

    info, _, _ = _parse(crafted)

    assert info is not None
    assert (info.protocol, info.src_port, info.dst_port) == ("UDP", 50000, 4789)
