"""Generate the PCAP fixtures that the tests read."""

from pathlib import Path

from scapy.all import ARP, Ether, IP, Raw, TCP, UDP, Packet, wrpcap

FIXTURE_DIR = Path(__file__).parent
BASE_TIME = 1758441600.0
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def basic_packets() -> list[Packet]:
    """Build the three frames of basic.pcap: TCP, UDP, and ARP."""
    tcp = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", tos=0xB8, flags="DF")
        / TCP(sport=40000, dport=80, flags="S", seq=1000)
    )
    udp = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=40000, dport=53)
        / b"udp-payload"
    )
    arp = (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            hwsrc=CLIENT_MAC,
            psrc="10.0.0.1",
            hwdst="00:00:00:00:00:00",
            pdst="10.0.0.2",
        )
    )
    return [tcp, udp, arp]


def tcp_handshake_packets() -> list[Packet]:
    """Build the three frames of a handshake, client 40000 to server 80."""
    client = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src="10.0.0.1", dst="10.0.0.2", proto=6
    )
    server = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=6
    )
    return [
        client / TCP(sport=40000, dport=80, flags="S", seq=1000),
        server / TCP(sport=80, dport=40000, flags="SA", seq=5000, ack=1001),
        client / TCP(sport=40000, dport=80, flags="A", seq=1001, ack=5001),
    ]


def tcp_data_packets() -> list[Packet]:
    """Build one PSH/ACK frame that carries 20 payload bytes."""
    frame = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA", seq=1001, ack=5001)
        / Raw(b"0123456789abcdefghij")
    )
    return [frame]


def udp_packets() -> list[Packet]:
    """Build one datagram that carries 12 payload bytes."""
    frame = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=53)
        / Raw(b"udp-payload!")
    )
    return [frame]


FIXTURES = {
    "basic.pcap": basic_packets,
    "tcp_handshake.pcap": tcp_handshake_packets,
    "tcp_data.pcap": tcp_data_packets,
    "udp.pcap": udp_packets,
}


def write_fixture(path: Path, packets: list[Packet]) -> None:
    """Write packets with fixed times, so the file is reproducible."""
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.5
    wrpcap(str(path), packets)


def build_all() -> None:
    everything: list[Packet] = []
    for name, build_packets in FIXTURES.items():
        write_fixture(FIXTURE_DIR / name, build_packets())
        everything.extend(build_packets())
    write_fixture(FIXTURE_DIR / "all.pcap", everything)


if __name__ == "__main__":
    build_all()
    print(f"wrote {len(FIXTURES) + 1} files to {FIXTURE_DIR}")
