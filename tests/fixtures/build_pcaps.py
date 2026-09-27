"""Generate the PCAP fixtures that the tests read."""

from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, Ether, IP, Raw, TCP, UDP, Packet, wrpcap

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


def _http_frame(client_to_server: bool, payload: bytes, sequence: int = 1001) -> Packet:
    """Build one PSH/ACK segment that carries an HTTP payload."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=6
        )
        return frame / TCP(sport=40000, dport=80, flags="PA", seq=sequence) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=6
    )
    return frame / TCP(sport=80, dport=40000, flags="PA", seq=sequence) / Raw(payload)


def http_get_packets() -> list[Packet]:
    """Build one GET request that names a host and a user agent."""
    payload = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: NT204/1.0\r\n"
        b"Accept: */*\r\n"
        b"\r\n"
    )
    return [_http_frame(True, payload)]


def http_post_packets() -> list[Packet]:
    """Build one POST request with a form body and its content length."""
    body = b"user=nt204"
    payload = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )
    return [_http_frame(True, payload)]


def http_response_packets() -> list[Packet]:
    """Build one 200 response with headers and a short body."""
    body = b"hello"
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Server: NT204\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )
    return [_http_frame(False, payload)]


def _dns_udp_frame(payload: bytes, client_to_server: bool = True) -> Packet:
    """Build one datagram that carries a DNS message."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=17
        )
        return frame / UDP(sport=40000, dport=53) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=17
    )
    return frame / UDP(sport=53, dport=40000) / Raw(payload)


def dns_query_packets() -> list[Packet]:
    """Build one A query for example.com."""
    query = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    return [_dns_udp_frame(query)]


def dns_response_packets() -> list[Packet]:
    """Build one response that answers the query with a single A record."""
    response = bytes(
        DNS(
            id=0x1234,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
        )
    )
    return [_dns_udp_frame(response, client_to_server=False)]


def dns_cname_packets() -> list[Packet]:
    """Build one response with a CNAME and the A record it points to."""
    response = bytes(
        DNS(
            id=0x1234,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="www.example.com", qtype="A"),
            an=[
                DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="example.com"),
                DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
            ],
        )
    )
    return [_dns_udp_frame(response, client_to_server=False)]


def dns_tcp_packets() -> list[Packet]:
    """Build one A query over TCP with its two-byte length prefix."""
    query = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    payload = len(query).to_bytes(2, "big") + query
    frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src="10.0.0.1", dst="10.0.0.2", proto=6
    )
    return [frame / TCP(sport=40000, dport=53, flags="PA") / Raw(payload)]


def _smtp_frame(client_to_server: bool, payload: bytes, sequence: int) -> Packet:
    """Build one PSH/ACK segment that carries an SMTP message."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=6
        )
        return frame / TCP(sport=40000, dport=25, flags="PA", seq=sequence) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=6
    )
    return frame / TCP(sport=25, dport=40000, flags="PA", seq=sequence) / Raw(payload)


def smtp_session_packets() -> list[Packet]:
    """Build the scripted SMTP dialogue of R8.6, one frame per message."""
    dialogue = [
        (False, b"220 mail.example.com ESMTP\r\n"),
        (True, b"EHLO client.example.com\r\n"),
        (
            False,
            b"250-mail.example.com\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 HELP\r\n",
        ),
        (True, b"MAIL FROM:<alice@example.com>\r\n"),
        (False, b"250 OK\r\n"),
        (True, b"RCPT TO:<bob@example.com>\r\n"),
        (False, b"250 OK\r\n"),
        (True, b"DATA\r\n"),
        (False, b"354 End data with <CR><LF>.<CR><LF>\r\n"),
        (True, b"Hello Bob.\r\n.\r\n"),
        (False, b"250 Message accepted\r\n"),
        (True, b"QUIT\r\n"),
        (False, b"221 Bye\r\n"),
    ]
    return [
        _smtp_frame(client_to_server, payload, 1001 + index * 100)
        for index, (client_to_server, payload) in enumerate(dialogue)
    ]


FIXTURES = {
    "basic.pcap": basic_packets,
    "tcp_handshake.pcap": tcp_handshake_packets,
    "tcp_data.pcap": tcp_data_packets,
    "udp.pcap": udp_packets,
    "http_get.pcap": http_get_packets,
    "http_post.pcap": http_post_packets,
    "http_response.pcap": http_response_packets,
    "dns_query.pcap": dns_query_packets,
    "dns_response.pcap": dns_response_packets,
    "dns_cname.pcap": dns_cname_packets,
    "dns_tcp.pcap": dns_tcp_packets,
    "smtp_session.pcap": smtp_session_packets,
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
