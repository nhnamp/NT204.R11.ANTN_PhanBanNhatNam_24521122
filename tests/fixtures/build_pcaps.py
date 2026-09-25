"""Generate the PCAP fixtures that the tests read."""

from pathlib import Path

from scapy.all import ARP, Ether, IP, TCP, UDP, Packet, wrpcap

FIXTURE_DIR = Path(__file__).parent
BASE_TIME = 1758441600.0
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"


def basic_packets() -> list[Packet]:
    """Build the three frames of basic.pcap: TCP, UDP, and ARP."""
    tcp = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
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


def build_basic(path: Path) -> None:
    """Write basic.pcap with fixed times, so the file is reproducible."""
    packets = basic_packets()
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + index * 0.5
    wrpcap(str(path), packets)


if __name__ == "__main__":
    target = FIXTURE_DIR / "basic.pcap"
    build_basic(target)
    print(f"wrote {target}")
