"""Generate the PCAP fixtures that the tests read."""

import base64
import json
import random
import struct
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    GRE,
    ICMP,
    IPv6,
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    Packet,
    wrpcap,
)

FIXTURE_DIR = Path(__file__).parent
MALFORMED_DIR = FIXTURE_DIR / "malformed"
EVENTS_DIR = FIXTURE_DIR / "events"
BASE_TIME = 1758441600.0
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
PCAP_MAGIC = 0xA1B2C3D4
LINK_ETHERNET = 1
LINK_NULL = 0
LINK_LINUX_SLL = 113
TCP_OFFSET = 34
UDP_LENGTH_OFFSET = 38
IP_LENGTH_OFFSET = 16


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


def _http_frame(
    client_to_server: bool, payload: bytes, sequence: int = 1001, port: int = 80
) -> Packet:
    """Build one PSH/ACK segment that carries an HTTP payload."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=6
        )
        return frame / TCP(sport=40000, dport=port, flags="PA", seq=sequence) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=6
    )
    return frame / TCP(sport=port, dport=40000, flags="PA", seq=sequence) / Raw(payload)


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


def _dns_udp_frame(payload: bytes, client_to_server: bool = True, port: int = 53) -> Packet:
    """Build one datagram that carries a DNS message."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=17
        )
        return frame / UDP(sport=40000, dport=port) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=17
    )
    return frame / UDP(sport=port, dport=40000) / Raw(payload)


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


def dns_udp_flow_packets() -> list[Packet]:
    """Build the query and the response of T10: one UDP flow, with the reversed 5-tuple in the reply."""
    return dns_query_packets() + dns_response_packets()


def _smtp_frame(
    client_to_server: bool, payload: bytes, sequence: int, port: int = 25
) -> Packet:
    """Build one PSH/ACK segment that carries an SMTP message."""
    if client_to_server:
        frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
            src="10.0.0.1", dst="10.0.0.2", proto=6
        )
        return frame / TCP(sport=40000, dport=port, flags="PA", seq=sequence) / Raw(payload)
    frame = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(
        src="10.0.0.2", dst="10.0.0.1", proto=6
    )
    return frame / TCP(sport=port, dport=40000, flags="PA", seq=sequence) / Raw(payload)


SMTP_DIALOGUE = [
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


def smtp_session_packets() -> list[Packet]:
    """Build the scripted SMTP dialogue of R8.6, one frame per message."""
    return [
        _smtp_frame(client_to_server, payload, 1001 + index * 100)
        for index, (client_to_server, payload) in enumerate(SMTP_DIALOGUE)
    ]


SMTP_HEADERS = (
    b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: NT204\r\n"
    b"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
)
SMTP_BASE64_MESSAGE = (
    SMTP_HEADERS
    + b"Content-Transfer-Encoding: base64\r\n\r\n"
    + base64.encodebytes("Xin chào Bob\r\n".encode("utf-8")).replace(b"\n", b"\r\n")
    + b".\r\n"
)
SMTP_QUOTED_PRINTABLE_MESSAGE = (
    SMTP_HEADERS
    + b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
    + b"caf=C3=A9 1+1=3D2, a long li=\r\nne\r\n"
    + b".\r\n"
)


def smtp_mime_packets() -> list[Packet]:
    """Build the dialogue of T03: a Base64 message, then a Quoted-Printable message."""
    envelope = SMTP_DIALOGUE[3:9]
    dialogue = (
        SMTP_DIALOGUE[:9]
        + [(True, SMTP_BASE64_MESSAGE), SMTP_DIALOGUE[10]]
        + envelope
        + [(True, SMTP_QUOTED_PRINTABLE_MESSAGE)]
        + SMTP_DIALOGUE[10:]
    )
    return [
        _smtp_frame(client_to_server, payload, 1001 + index * 100)
        for index, (client_to_server, payload) in enumerate(dialogue)
    ]


def unknown_protocol_packets() -> list[Packet]:
    """Build one packet per unsupported case of TC-11, in a fixed order."""
    inner = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=40000, dport=80, flags="S")
    return [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=40000, dport=80, flags="S"),
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(hwsrc=CLIENT_MAC, psrc="10.0.0.1", hwdst="00:00:00:00:00:00", pdst="10.0.0.2"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / ICMP(type=8, id=1, seq=1)
        / Raw(b"ping"),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2") / GRE() / inner,
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=40000, dport=4444, flags="PA", seq=1001)
        / Raw(random.Random(11).randbytes(64)),
    ]


HTTP_BONUS_GET = b"GET /bonus HTTP/1.1\r\nHost: example.com\r\n\r\n"
HTTP_BONUS_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"


def bonus_http_8080_packets() -> list[Packet]:
    """Build a GET on port 8080 and its response."""
    return [
        _http_frame(True, HTTP_BONUS_GET, 1001, 8080),
        _http_frame(False, HTTP_BONUS_RESPONSE, 2001, 8080),
    ]


def bonus_http_3000_packets() -> list[Packet]:
    """Build a POST on port 3000, which no port hint names."""
    body = b"user=nt204"
    payload = (
        b"POST /bonus HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"\r\n"
        + body
    )
    return [_http_frame(True, payload, 1001, 3000)]


def bonus_dns_1053_packets() -> list[Packet]:
    """Build a query and its answer on port 1053, which no port hint names."""
    query = bytes(DNS(id=0x4321, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    response = bytes(
        DNS(
            id=0x4321,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
        )
    )
    return [_dns_udp_frame(query, True, 1053), _dns_udp_frame(response, False, 1053)]


def bonus_dns_tcp_9053_packets() -> list[Packet]:
    """Build a DNS query over TCP on port 9053, which no port hint names."""
    query = bytes(DNS(id=0x4321, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    payload = len(query).to_bytes(2, "big") + query
    frame = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(
        src="10.0.0.1", dst="10.0.0.2", proto=6
    )
    return [frame / TCP(sport=40000, dport=9053, flags="PA", seq=1001) / Raw(payload)]


def bonus_smtp_2526_packets() -> list[Packet]:
    """Build the P8 dialogue on port 2526, which no port hint names (2525 is a hint)."""
    return [
        _smtp_frame(client_to_server, payload, 1001 + index * 100, 2526)
        for index, (client_to_server, payload) in enumerate(SMTP_DIALOGUE)
    ]


def bonus_traps_packets() -> list[Packet]:
    """Build random bytes on 80, 53, and 25, then an HTTP request on 53."""
    noise = random.Random(13).randbytes(64)
    return [
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=80, flags="PA", seq=1001)
        / Raw(noise),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=53)
        / Raw(noise),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=25, flags="PA", seq=1001)
        / Raw(noise),
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=53, flags="PA", seq=1001)
        / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]


def _http_request(method: bytes, target: bytes, body: bytes = b"", content_type: bytes | None = None) -> bytes:
    """Build an HTTP request, with a content length when it has a body."""
    headers = b"Host: example.com\r\n"
    if content_type is not None:
        headers += b"Content-Type: " + content_type + b"\r\n"
    if body:
        headers += f"Content-Length: {len(body)}\r\n".encode("ascii")
    return method + b" " + target + b" HTTP/1.1\r\n" + headers + b"\r\n" + body


def _http_reply(body: bytes, content_type: bytes | None = None) -> bytes:
    """Build a 200 response, with a content length."""
    headers = b""
    if content_type is not None:
        headers += b"Content-Type: " + content_type + b"\r\n"
    return b"HTTP/1.1 200 OK\r\n" + headers + f"Content-Length: {len(body)}\r\n".encode("ascii") + b"\r\n" + body


def http_percent_packets() -> list[Packet]:
    """Build the requests of T01: percent encoding, a plus sign, a form body, and a bad escape."""
    form = b"user=%27+OR+1%3D1&note=a%2Bb"
    return [
        _http_frame(True, _http_request(b"GET", b"/search?q=%27%20OR%201%3D1"), 1001),
        _http_frame(True, _http_request(b"GET", b"/a+b?c+d=e%2Bf"), 1101),
        _http_frame(
            True,
            _http_request(b"POST", b"/login", form, b"application/x-www-form-urlencoded"),
            1201,
        ),
        _http_frame(True, _http_request(b"GET", b"/p?q=%zz"), 1301),
    ]


def http_entity_packets() -> list[Packet]:
    """Build the messages of T02: an entity in HTML, an entity with no semicolon, and no content type."""
    return [
        _http_frame(False, _http_reply(b"&lt;script&gt;alert(1)&lt;/script&gt;", b"text/html"), 2001),
        _http_frame(True, _http_request(b"POST", b"/note", b"a=1&lt=2", b"text/plain"), 1001),
        _http_frame(False, _http_reply(b"&lt;b&gt;"), 2101),
    ]


def invalid_utf8_packets() -> list[Packet]:
    """Build the payloads of T04: bad bytes in an HTTP body, a few bad bytes in text, and binary data."""
    base = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
    return [
        _http_frame(False, _http_reply(b"\xff\xfe\x80 some readable text", b"text/html"), 2001),
        base / TCP(sport=40000, dport=4444, flags="PA", seq=1001) / Raw(b"plain text \xff\xfe\x80 more plain text"),
        base / TCP(sport=40000, dport=4444, flags="PA", seq=1101) / Raw(random.Random(17).randbytes(64)),
    ]


def normalization_packets() -> list[Packet]:
    """Build the packets of T05: two GET requests that differ in case and format, and a DNS query in capitals."""
    first = (
        b"GET /a/%2e%2e/b?q=1 HTTP/1.1\r\n"
        b"HOST: EXAMPLE.com.:80\r\n"
        b"X-Test: a\r\n"
        b"x-TEST: b\r\n\r\n"
    )
    second = b"GET /b?q=1 HTTP/1.1\r\nhost: example.com\r\nx-test: a\r\nx-test: b\r\n\r\n"
    query = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="WWW.Example.COM", qtype="A")))
    return [_http_frame(True, first, 1001), _http_frame(True, second, 1201), _dns_udp_frame(query)]


Endpoint = tuple[str, int]
DEFAULT_CLIENT: Endpoint = ("10.0.0.1", 40000)
DEFAULT_SERVER: Endpoint = ("10.0.0.2", 80)
FLOW_REQUEST = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
FLOW_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
STATS_SERVER: Endpoint = ("10.0.0.2", 4444)
# Offsets in seconds from BASE_TIME. A fixture without an entry uses BASE_TIME + index * 0.5.
FIXTURE_TIMES = {
    "flow_stats.pcap": [0.0, 0.01, 0.02, 1.0, 1.1, 2.5, 2.6, 4.0, 4.1, 4.2],
}


def _tcp_segment(
    from_client: bool,
    flags: str,
    seq: int,
    ack: int = 0,
    payload: bytes = b"",
    client: Endpoint = DEFAULT_CLIENT,
    server: Endpoint = DEFAULT_SERVER,
) -> Packet:
    """Build one TCP segment of a connection between a client and a server."""
    source, destination = (client, server) if from_client else (server, client)
    macs = (CLIENT_MAC, SERVER_MAC) if from_client else (SERVER_MAC, CLIENT_MAC)
    return (
        Ether(src=macs[0], dst=macs[1])
        / IP(src=source[0], dst=destination[0], proto=6)
        / TCP(sport=source[1], dport=destination[1], flags=flags, seq=seq, ack=ack)
        / Raw(payload)
    )


def _handshake(client: Endpoint = DEFAULT_CLIENT, server: Endpoint = DEFAULT_SERVER) -> list[Packet]:
    """Build SYN, SYN/ACK, and ACK. The client starts at sequence 1000 and the server at 5000."""
    return [
        _tcp_segment(True, "S", 1000, 0, b"", client, server),
        _tcp_segment(False, "SA", 5000, 1001, b"", client, server),
        _tcp_segment(True, "A", 1001, 5001, b"", client, server),
    ]


def flow_http_packets() -> list[Packet]:
    """Build one HTTP exchange inside one connection: handshake, request, ACK, response, ACK."""
    after_request = 1001 + len(FLOW_REQUEST)
    after_response = 5001 + len(FLOW_RESPONSE)
    return _handshake() + [
        _tcp_segment(True, "PA", 1001, 5001, FLOW_REQUEST),
        _tcp_segment(False, "A", 5001, after_request),
        _tcp_segment(False, "PA", 5001, after_request, FLOW_RESPONSE),
        _tcp_segment(True, "A", after_request, after_response),
    ]


def tcp_close_fin_packets() -> list[Packet]:
    """Build a handshake and a close where each side sends a FIN and the client sends the last ACK."""
    return _handshake() + [
        _tcp_segment(True, "FA", 1001, 5001),
        _tcp_segment(False, "A", 5001, 1002),
        _tcp_segment(False, "FA", 5001, 1002),
        _tcp_segment(True, "A", 1002, 5002),
    ]


def tcp_close_rst_packets() -> list[Packet]:
    """Build a handshake, a request, and a reset from the server."""
    return _handshake() + [
        _tcp_segment(True, "PA", 1001, 5001, FLOW_REQUEST),
        _tcp_segment(False, "RA", 5001, 1001 + len(FLOW_REQUEST)),
    ]


def concurrent_flows_packets() -> list[Packet]:
    """Build four flows whose packets alternate: three TCP connections and one UDP exchange."""
    first = (("10.0.0.1", 40000), ("10.0.0.2", 80))
    second = (("10.0.0.1", 40001), ("10.0.0.2", 80))
    third = (("10.0.0.1", 40002), ("10.0.0.3", 80))
    query = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    answer = DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34")
    response = bytes(DNS(id=0x1234, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com", qtype="A"), an=answer))
    udp = Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
    udp_back = Ether(src=SERVER_MAC, dst=CLIENT_MAC) / IP(src="10.0.0.2", dst="10.0.0.1", proto=17)
    return [
        _tcp_segment(True, "S", 1000, 0, b"", *first),
        _tcp_segment(True, "S", 1000, 0, b"", *second),
        _tcp_segment(False, "SA", 5000, 1001, b"", *first),
        _tcp_segment(True, "S", 1000, 0, b"", *third),
        _tcp_segment(False, "SA", 5000, 1001, b"", *second),
        _tcp_segment(True, "A", 1001, 5001, b"", *first),
        udp / UDP(sport=40003, dport=53) / Raw(query),
        _tcp_segment(False, "SA", 5000, 1001, b"", *third),
        _tcp_segment(True, "A", 1001, 5001, b"", *second),
        udp_back / UDP(sport=53, dport=40003) / Raw(response),
        _tcp_segment(True, "A", 1001, 5001, b"", *third),
        _tcp_segment(True, "PA", 1001, 5001, FLOW_REQUEST, *first),
    ]


def flow_stats_packets() -> list[Packet]:
    """Build a connection of 10 packets with known flags and sizes. FIXTURE_TIMES gives it uneven times."""
    request, reply = b"a" * 100, b"b" * 300
    client, server = DEFAULT_CLIENT, STATS_SERVER

    def segment(from_client: bool, flags: str, seq: int, ack: int = 0, payload: bytes = b"") -> Packet:
        return _tcp_segment(from_client, flags, seq, ack, payload, client, server)

    return [
        segment(True, "S", 1000),
        segment(False, "SA", 5000, 1001),
        segment(True, "A", 1001, 5001),
        segment(True, "PA", 1001, 5001, request),
        segment(False, "A", 5001, 1101),
        segment(False, "PA", 5001, 1101, reply),
        segment(True, "A", 1101, 5301),
        segment(True, "FA", 1101, 5301),
        segment(False, "FA", 5301, 1102),
        segment(True, "A", 1102, 5302),
    ]


def expected_flow_stats() -> dict:
    """Compute the flow record counters of flow_stats.pcap from the packets, not from the tracker."""
    packets = flow_stats_packets()
    times = FIXTURE_TIMES["flow_stats.pcap"]
    forward = [p for p in packets if p[IP].src == DEFAULT_CLIENT[0]]
    backward = [p for p in packets if p[IP].src != DEFAULT_CLIENT[0]]
    flags = [str(p[TCP].flags) for p in packets]
    return {
        "packet_count": len(packets),
        "byte_count": sum(len(bytes(p)) for p in packets),
        "forward_packet_count": len(forward),
        "forward_byte_count": sum(len(bytes(p)) for p in forward),
        "backward_packet_count": len(backward),
        "backward_byte_count": sum(len(bytes(p)) for p in backward),
        "syn_count": sum("S" in f for f in flags),
        "ack_count": sum("A" in f for f in flags),
        "fin_count": sum("F" in f for f in flags),
        "rst_count": sum("R" in f for f in flags),
        "duration": round(times[-1] - times[0], 6),
    }


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
    "dns_udp_flow.pcap": dns_udp_flow_packets,
    "smtp_session.pcap": smtp_session_packets,
    "smtp_mime.pcap": smtp_mime_packets,
    "unknown_protocols.pcap": unknown_protocol_packets,
    "bonus_http_8080.pcap": bonus_http_8080_packets,
    "bonus_http_3000.pcap": bonus_http_3000_packets,
    "bonus_dns_1053.pcap": bonus_dns_1053_packets,
    "bonus_dns_tcp_9053.pcap": bonus_dns_tcp_9053_packets,
    "bonus_smtp_2526.pcap": bonus_smtp_2526_packets,
    "bonus_traps.pcap": bonus_traps_packets,
    "http_percent.pcap": http_percent_packets,
    "http_entity.pcap": http_entity_packets,
    "invalid_utf8.pcap": invalid_utf8_packets,
    "normalization.pcap": normalization_packets,
    "flow_http.pcap": flow_http_packets,
    "tcp_close_fin.pcap": tcp_close_fin_packets,
    "tcp_close_rst.pcap": tcp_close_rst_packets,
    "concurrent_flows.pcap": concurrent_flows_packets,
    "flow_stats.pcap": flow_stats_packets,
}


DNS_HEADER = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
DNS_QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"
DNS_ANSWER_OFFSET = len(DNS_HEADER) + len(DNS_QUESTION)


def _pcap_bytes(frames: list[bytes], link_type: int = LINK_ETHERNET) -> bytes:
    """Build a PCAP file, because Scapy cannot build a header that breaks its own rules."""
    data = bytearray(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, link_type))
    for index, frame in enumerate(frames):
        data += struct.pack("<IIII", int(BASE_TIME) + index, 0, len(frame), len(frame))
        data += frame
    return bytes(data)


def _write_pcap(path: Path, frames: list[bytes], link_type: int = LINK_ETHERNET) -> None:
    """Write raw frames, so a crafted header needs no Scapy packet model."""
    path.write_bytes(_pcap_bytes(frames, link_type))


def _ip_tcp_frame(payload: bytes = b"", dport: int = 80) -> bytes:
    """Build one valid Ethernet/IPv4/TCP frame, ready for byte surgery."""
    return bytes(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=6)
        / TCP(sport=40000, dport=dport, flags="PA", seq=1000)
        / Raw(payload)
    )


def _ip_udp_frame(payload: bytes = b"", dport: int = 53) -> bytes:
    """Build one valid Ethernet/IPv4/UDP frame, ready for byte surgery."""
    return bytes(
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src="10.0.0.1", dst="10.0.0.2", proto=17)
        / UDP(sport=40000, dport=dport)
        / Raw(payload)
    )


def _set_ip_length(frame: bytes, value: int) -> bytes:
    """Patch the IPv4 total length field."""
    return frame[:IP_LENGTH_OFFSET] + value.to_bytes(2, "big") + frame[IP_LENGTH_OFFSET + 2 :]


def _set_udp_length(frame: bytes, value: int) -> bytes:
    """Patch the UDP length field."""
    return frame[:UDP_LENGTH_OFFSET] + value.to_bytes(2, "big") + frame[UDP_LENGTH_OFFSET + 2 :]


def _dns_response_with_answer_name(name: bytes) -> bytes:
    """Build a DNS response whose answer name breaks one R7.5 safety rule."""
    record = name + b"\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x01\x02\x03\x04"
    return DNS_HEADER + DNS_QUESTION + record


def malformed_files() -> dict[str, tuple[list[bytes], int]]:
    """Build the R9.2 corpus, keyed by file name."""
    tcp = _ip_tcp_frame(b"x")
    udp = _ip_udp_frame(b"udp-payload")
    noise = random.Random(9).randbytes(64)
    long_line = b"GET /" + b"a" * 20480 + b" HTTP/1.1"
    many_headers = b"GET / HTTP/1.1\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(300))
    tunnel = IP(src="10.0.0.3", dst="10.0.0.4", proto=6) / TCP(sport=40000, dport=80)
    return {
        "01_ipv4_ihl3.pcap": ([tcp[:14] + b"\x43" + tcp[15:]], LINK_ETHERNET),
        "02_ipv4_length_large.pcap": ([_set_ip_length(tcp, len(tcp) + 100)], LINK_ETHERNET),
        "03_ipv4_length_small.pcap": ([_set_ip_length(tcp, 10)], LINK_ETHERNET),
        "04_tcp_data_offset2.pcap": ([tcp[:TCP_OFFSET + 12] + b"\x20" + tcp[TCP_OFFSET + 13 :]], LINK_ETHERNET),
        "05_tcp_header_cut.pcap": ([tcp[: TCP_OFFSET + 8]], LINK_ETHERNET),
        "06_udp_length_large.pcap": ([_set_udp_length(udp, 60000)], LINK_ETHERNET),
        "07_udp_length_small.pcap": ([_set_udp_length(udp, 4)], LINK_ETHERNET),
        "08_dns_answer_pointer_loop.pcap": (
            [_ip_udp_frame(_dns_response_with_answer_name(b"\x01a\xc0" + bytes([DNS_ANSWER_OFFSET])))],
            LINK_ETHERNET,
        ),
        "09_dns_question_count.pcap": (
            [_ip_udp_frame(b"\x12\x34\x01\x00" + (65535).to_bytes(2, "big") + b"\x00" * 6)],
            LINK_ETHERNET,
        ),
        "10_dns_answer_long_label.pcap": (
            # 100 is a label length above 63. A length octet of 192 or more is a pointer instead.
            [_ip_udp_frame(_dns_response_with_answer_name(bytes([100]) + b"a" * 100))],
            LINK_ETHERNET,
        ),
        "11_http_long_request_line.pcap": ([_ip_tcp_frame(long_line)], LINK_ETHERNET),
        "12_http_many_headers.pcap": ([_ip_tcp_frame(many_headers)], LINK_ETHERNET),
        "13_smtp_many_lines.pcap": ([_ip_tcp_frame(b"NOOP\r\n" * 5000, dport=25)], LINK_ETHERNET),
        "14_random_bytes_on_known_ports.pcap": (
            [_ip_tcp_frame(noise), _ip_udp_frame(noise), _ip_tcp_frame(noise, dport=25)],
            LINK_ETHERNET,
        ),
        "15_invalid_text_bytes.pcap": ([_ip_tcp_frame(b"\xff\xfe\x80\x81\x00\x01\x02\x03" * 8)], LINK_ETHERNET),
        "16_empty_frames.pcap": ([b"", b"\x00"], LINK_ETHERNET),
        "17_unsupported_protocols.pcap": (
            [
                bytes(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP()),
                bytes(
                    Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff")
                    / ARP(hwsrc=CLIENT_MAC, psrc="10.0.0.1", hwdst="00:00:00:00:00:00", pdst="10.0.0.2")
                ),
                bytes(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2", proto=1) / ICMP()),
                bytes(Ether(src=CLIENT_MAC, dst=SERVER_MAC) / IP(src="10.0.0.1", dst="10.0.0.2", proto=47) / GRE() / tunnel),
            ],
            LINK_ETHERNET,
        ),
        "20_null_link.pcap": ([struct.pack("<I", 2) + bytes(tunnel)], LINK_NULL),
        "20_linux_sll.pcap": (
            [
                struct.pack(">HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x01\x00\x00", 0x0800)
                + bytes(tunnel)
            ],
            LINK_LINUX_SLL,
        ),
    }


def build_malformed() -> None:
    """Write the R9.2 corpus, one crafted file per item."""
    MALFORMED_DIR.mkdir(exist_ok=True)
    for name, (frames, link_type) in malformed_files().items():
        _write_pcap(MALFORMED_DIR / name, frames, link_type)
    cut = _pcap_bytes([_ip_udp_frame(b"udp-payload")])
    (MALFORMED_DIR / "18_cut_final_record.pcap").write_bytes(cut[:-10])
    (MALFORMED_DIR / "19_not_a_pcap.txt").write_text("this file is not a capture file\n")


def _event(**changes: object) -> dict:
    """Build a minimal event, as an events file can hold it."""
    event = {
        "timestamp": BASE_TIME,
        "network": {"src_ip": "2001:db8::1", "dst_ip": "10.0.0.2", "frag_offset": 0},
        "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80, "flags": ["SYN"]},
        "app_protocol": "HTTP",
        "status": "ok",
    }
    event.update(changes)
    return event


def events_files() -> dict[str, list[bytes]]:
    """Build the lines of the events files, keyed by file name."""

    def lines(*events: dict) -> list[bytes]:
        return [json.dumps(event).encode() for event in events]

    variant = _event(
        timestamp="2025-09-21T08:00:00",
        network={"src_ip": "2001:DB8::1", "dst_ip": "10.0.0.2"},
        transport={"protocol": "tcp", "src_port": "40000", "dst_port": "80", "flags": ["syn"]},
        app_protocol="Http",
    )
    leading_zero = _event(network={"src_ip": "010.0.0.1", "dst_ip": "10.0.0.2"})
    bad_port = _event(transport={"protocol": "TCP", "src_port": 40000, "dst_port": 70000})
    arp_like = _event(network=None, transport=None, app_protocol="UNKNOWN", status="unsupported")
    return {
        "protocol_and_ip.jsonl": lines(_event(), variant, leading_zero),
        "missing_fields.jsonl": lines(
            {"timestamp": BASE_TIME, "network": _event()["network"], "transport": _event()["transport"]},
            {"timestamp": BASE_TIME},
        ),
        "invalid_events.jsonl": [
            b"{}",
            b"[]",
            b'"text"',
            b"{not json",
            *lines(bad_port, _event(timestamp=True), _event(timestamp="9999-12-31T23:59:59"), arp_like),
        ],
    }


def build_events() -> None:
    """Write the events files, one JSON object per line."""
    EVENTS_DIR.mkdir(exist_ok=True)
    for name, lines in events_files().items():
        (EVENTS_DIR / name).write_bytes(b"\n".join(lines) + b"\n")


def write_fixture(path: Path, packets: list[Packet], offsets: list[float] | None = None) -> None:
    """Write packets with fixed times, so the file is reproducible."""
    for index, packet in enumerate(packets):
        packet.time = BASE_TIME + (offsets[index] if offsets else index * 0.5)
    wrpcap(str(path), packets)


def build_all() -> None:
    everything: list[Packet] = []
    for name, build_packets in FIXTURES.items():
        write_fixture(FIXTURE_DIR / name, build_packets(), FIXTURE_TIMES.get(name))
        everything.extend(build_packets())
    write_fixture(FIXTURE_DIR / "all.pcap", everything)
    build_malformed()
    build_events()


if __name__ == "__main__":
    build_all()
    print(f"wrote {len(FIXTURES) + 1} fixtures and the malformed corpus to {FIXTURE_DIR}")
