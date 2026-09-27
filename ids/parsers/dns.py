"""Read DNS names and parse DNS messages (RFC 1035 section 4.1) with bounds and pointer safety.

A name is a sequence of length-prefixed labels, closed by a zero label.
The two high bits of a length octet mark a two-byte pointer to an earlier offset.
"""

import ipaddress

from ids.events import DnsAnswer, DnsInfo, DnsQuestion, ParseError, TransportInfo

MAX_LABEL = 63
MAX_NAME = 255
MAX_JUMPS = 64
POINTER_MASK = 0xC0

HEADER_LEN = 12
MAX_RECORDS = 64
FLAG_NAMES = (("AA", 0x0400), ("TC", 0x0200), ("RD", 0x0100), ("RA", 0x0080))
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28


class TruncatedError(ValueError):
    """The message ends before a field that its own lengths declare."""


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Return the name at offset, and the offset just after the name.

    A violation of the DNS name limits raises ValueError, so a crafted packet
    cannot send the reader out of bounds or into a pointer loop (R7.5).
    """
    if not 0 <= offset < len(data):
        raise TruncatedError("name starts outside the message")
    labels: list[str] = []
    length = 0
    jumps = 0
    after: int | None = None
    position = offset
    while True:
        if position >= len(data):
            raise TruncatedError("name runs past the message")
        size = data[position]
        if size & POINTER_MASK == POINTER_MASK:
            if position + 1 >= len(data):
                raise TruncatedError("compression pointer is cut")
            target = ((size & 0x3F) << 8) | data[position + 1]
            if target >= position:
                raise ValueError("compression pointer does not point backwards")
            jumps += 1
            if jumps > MAX_JUMPS:
                raise ValueError("name uses more than 64 compression jumps")
            if after is None:
                after = position + 2
            position = target
            continue
        if size > MAX_LABEL:
            raise ValueError("label is longer than 63 bytes")
        position += 1
        if size == 0:
            return ".".join(labels), position if after is None else after
        if position + size > len(data):
            raise TruncatedError("label runs past the message")
        labels.append(data[position : position + size].decode("ascii", errors="replace"))
        position += size
        length += size + 1
        if length + 1 > MAX_NAME:
            raise ValueError("name is longer than 255 bytes")


def parse_dns(payload: bytes, transport: TransportInfo) -> tuple[DnsInfo, list[ParseError]]:
    """Parse one DNS message, and return what is readable before the first fault."""
    errors: list[ParseError] = []
    data = payload
    if transport.protocol == "TCP":
        if len(payload) < 2:
            return _empty(), [_error("truncated", "length prefix is cut")]
        data = payload[2 : 2 + int.from_bytes(payload[:2], "big")]
    if len(data) < HEADER_LEN:
        return _empty(), [_error("truncated", "header is cut")]

    flags = int.from_bytes(data[2:4], "big")
    qdcount = int.from_bytes(data[4:6], "big")
    ancount = int.from_bytes(data[6:8], "big")
    nscount = int.from_bytes(data[8:10], "big")
    arcount = int.from_bytes(data[10:12], "big")
    if qdcount > MAX_RECORDS or ancount > MAX_RECORDS:
        errors.append(
            ParseError(stage="dns", type="limit", message="more than 64 records in a section")
        )
    questions, offset = _questions(data, min(qdcount, MAX_RECORDS), HEADER_LEN, errors)
    answers, _ = _answers(data, min(ancount, MAX_RECORDS), offset, errors)

    rcode = flags & 0xF
    return DnsInfo(
        transaction_id=int.from_bytes(data[0:2], "big"),
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0xF,
        flags=[name for name, mask in FLAG_NAMES if flags & mask],
        rcode=rcode,
        rcode_name=RCODE_NAMES.get(rcode, str(rcode)),
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
        questions=questions,
        answers=answers,
        partial=bool(errors),
    ), errors


def _questions(
    data: bytes, count: int, offset: int, errors: list[ParseError]
) -> tuple[list[DnsQuestion], int]:
    questions: list[DnsQuestion] = []
    for _ in range(count):
        try:
            name, position = read_name(data, offset)
            if position + 4 > len(data):
                raise TruncatedError("question is cut")
            qtype = int.from_bytes(data[position : position + 2], "big")
            qclass = int.from_bytes(data[position + 2 : position + 4], "big")
        except ValueError as exc:
            errors.append(_record_error(exc))
            break
        questions.append(
            DnsQuestion(
                name=name, qtype=qtype, qtype_name=_type_name(qtype), qclass=qclass
            )
        )
        offset = position + 4
    return questions, offset


def _answers(
    data: bytes, count: int, offset: int, errors: list[ParseError]
) -> tuple[list[DnsAnswer], int]:
    answers: list[DnsAnswer] = []
    for _ in range(count):
        try:
            name, position = read_name(data, offset)
            if position + 10 > len(data):
                raise TruncatedError("record header is cut")
            rtype = int.from_bytes(data[position : position + 2], "big")
            rclass = int.from_bytes(data[position + 2 : position + 4], "big")
            ttl = int.from_bytes(data[position + 4 : position + 8], "big")
            rdlength = int.from_bytes(data[position + 8 : position + 10], "big")
            start = position + 10
            end = start + rdlength
            if end > len(data):
                raise TruncatedError("record data is cut")
            rdata = _rdata(data, rtype, start, end)
        except ValueError as exc:
            errors.append(_record_error(exc))
            break
        answers.append(
            DnsAnswer(
                name=name,
                type=rtype,
                type_name=_type_name(rtype),
                rclass=rclass,
                ttl=ttl,
                rdata=rdata,
            )
        )
        offset = end
    return answers, offset


def _rdata(data: bytes, rtype: int, start: int, end: int) -> str | dict[str, object] | list[str]:
    if rtype == TYPE_A and end - start == 4:
        return str(ipaddress.IPv4Address(data[start:end]))
    if rtype == TYPE_AAAA and end - start == 16:
        return str(ipaddress.IPv6Address(data[start:end]))
    if rtype in (TYPE_CNAME, TYPE_NS, TYPE_PTR):
        name, position = read_name(data, start)
        if position > end:
            raise ValueError("record name is longer than the record")
        return name
    if rtype == TYPE_MX:
        if end - start < 3:
            raise TruncatedError("MX record is cut")
        name, position = read_name(data, start + 2)
        if position > end:
            raise ValueError("record name is longer than the record")
        preference = int.from_bytes(data[start : start + 2], "big")
        return {"preference": preference, "exchange": name}
    if rtype == TYPE_TXT:
        return _txt(data, start, end)
    if rtype == TYPE_SOA:
        return _soa(data, start, end)
    return {"raw_hex": data[start:end].hex()}


def _txt(data: bytes, start: int, end: int) -> list[str]:
    strings: list[str] = []
    position = start
    while position < end:
        size = data[position]
        position += 1
        if position + size > end:
            raise TruncatedError("text record is cut")
        strings.append(data[position : position + size].decode("utf-8", errors="replace"))
        position += size
    return strings


def _soa(data: bytes, start: int, end: int) -> dict[str, object]:
    mname, position = read_name(data, start)
    rname, position = read_name(data, position)
    if position + 20 > end:
        raise TruncatedError("SOA record is cut")
    values = [
        int.from_bytes(data[position + index : position + index + 4], "big")
        for index in range(0, 20, 4)
    ]
    return {
        "mname": mname,
        "rname": rname,
        "serial": values[0],
        "refresh": values[1],
        "retry": values[2],
        "expire": values[3],
        "minimum": values[4],
    }


def _type_name(rtype: int) -> str:
    return TYPE_NAMES.get(rtype, str(rtype))


def _error(kind: str, message: str) -> ParseError:
    return ParseError(stage="dns", type=kind, message=message)


def _record_error(exc: ValueError) -> ParseError:
    # A cut message is a capture or transport problem. A broken structure is a DNS fault.
    return _error("truncated" if isinstance(exc, TruncatedError) else "malformed", str(exc))


def _empty() -> DnsInfo:
    return DnsInfo(
        transaction_id=0,
        is_response=False,
        opcode=0,
        flags=[],
        rcode=0,
        rcode_name="",
        qdcount=0,
        ancount=0,
        nscount=0,
        arcount=0,
        questions=[],
        answers=[],
        partial=True,
    )
