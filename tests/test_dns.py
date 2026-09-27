import pytest

from ids.events import TransportInfo
from ids.parsers.dns import parse_dns, read_name


def _name(sizes: list[int]) -> bytes:
    """Encode a name with one plain label per requested size."""
    return b"".join(bytes([size]) + b"a" * size for size in sizes) + b"\x00"


def _pointer_chain(jumps: int) -> tuple[bytes, int]:
    """Encode a chain of backward pointers, so the reader must follow every one."""
    data = bytearray(b"\x00" + b"\x00" * (2 * jumps))
    for index in range(1, jumps + 1):
        position = 2 * index - 1
        data[position] = 0xC0
        data[position + 1] = 0 if index == 1 else 2 * (index - 1) - 1
    return bytes(data), 2 * jumps - 1


def test_plain_name_is_read() -> None:
    data = b"\x07example\x03com\x00\x00\x01\x00\x01"

    assert read_name(data, 0) == ("example.com", 13)


def test_compressed_name_is_read() -> None:
    data = b"\x07example\x03com\x00\x03www\xc0\x00"

    assert read_name(data, 13) == ("www.example.com", 19)


def test_a_name_of_exactly_255_wire_bytes_is_read() -> None:
    name, offset = read_name(_name([63, 63, 63, 61]), 0)

    assert name.count(".") == 3
    assert offset == 255


def test_64_jumps_are_allowed() -> None:
    data, offset = _pointer_chain(64)

    assert read_name(data, offset) == ("", offset + 2)


def test_the_jump_limit_is_enforced() -> None:
    data, offset = _pointer_chain(65)

    with pytest.raises(ValueError):
        read_name(data, offset)


@pytest.mark.parametrize(
    ("data", "offset"),
    [
        (b"\xc0\x02\x00", 0),
        (b"\xc0\x00", 0),
        (b"\x03www\xc0", 4),
        (b"\x05abc", 0),
        (b"\x03www", 0),
        (b"\x40" + b"a" * 64, 0),
        (_name([60, 60, 60, 60, 60]), 0),
    ],
)
def test_a_violation_of_the_limits_raises(data: bytes, offset: int) -> None:
    with pytest.raises(ValueError):
        read_name(data, offset)


def _transport(protocol: str = "UDP") -> TransportInfo:
    return TransportInfo(protocol=protocol, src_port=40000, dst_port=53, payload_len=0)


def _header(flags: int = 0x0100, question: int = 1, answer: int = 0) -> bytes:
    return b"\x12\x34" + b"".join(
        value.to_bytes(2, "big") for value in (flags, question, answer, 0, 0)
    )


def _question(name: bytes = b"\x07example\x03com\x00", qtype: int = 1) -> bytes:
    return name + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")


def _response(rtype: int, rdata: bytes, ttl: int = 300) -> bytes:
    record = (
        b"\xc0\x0c"
        + rtype.to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + ttl.to_bytes(4, "big")
        + len(rdata).to_bytes(2, "big")
        + rdata
    )
    return _header(flags=0x8180, answer=1) + _question() + record


def test_a_query_is_parsed() -> None:
    info, errors = parse_dns(_header() + _question(), _transport())

    assert errors == []
    assert (info.transaction_id, info.is_response, info.opcode) == (0x1234, False, 0)
    assert (info.flags, info.rcode, info.rcode_name) == (["RD"], 0, "NOERROR")
    assert (info.qdcount, info.ancount, info.nscount, info.arcount) == (1, 0, 0, 0)
    assert info.partial is False
    assert len(info.questions) == 1
    assert (info.questions[0].name, info.questions[0].qtype) == ("example.com", 1)
    assert (info.questions[0].qtype_name, info.questions[0].qclass) == ("A", 1)


def test_one_answer_is_parsed() -> None:
    info, errors = parse_dns(_response(1, bytes([93, 184, 216, 34])), _transport())

    assert errors == []
    assert info.is_response is True
    assert info.flags == ["RD", "RA"]
    assert len(info.answers) == 1
    answer = info.answers[0]
    assert (answer.name, answer.type_name, answer.ttl) == ("example.com", "A", 300)
    assert answer.rdata == "93.184.216.34"


def test_a_cname_chain_is_parsed() -> None:
    message = (
        _header(flags=0x8180, answer=2)
        + _question(b"\x03www\x07example\x03com\x00")
        + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x01\x2c\x00\x02\xc0\x10"
        + b"\xc0\x10\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22"
    )

    info, errors = parse_dns(message, _transport())

    assert errors == []
    assert [(answer.name, answer.type_name) for answer in info.answers] == [
        ("www.example.com", "CNAME"),
        ("example.com", "A"),
    ]
    assert info.answers[0].rdata == "example.com"
    assert info.answers[1].rdata == "93.184.216.34"


def test_a_tcp_prefix_is_stripped() -> None:
    query = _header() + _question()
    payload = len(query).to_bytes(2, "big") + query

    info, errors = parse_dns(payload, _transport("TCP"))

    assert errors == []
    assert info.questions[0].name == "example.com"


@pytest.mark.parametrize(
    ("rtype", "rdata", "expected"),
    [
        (1, bytes([1, 2, 3, 4]), "1.2.3.4"),
        (28, bytes.fromhex("20010db8000000000000000000000001"), "2001:db8::1"),
        (2, b"\x02ns\xc0\x0c", "ns.example.com"),
        (5, b"\x03www\xc0\x0c", "www.example.com"),
        (12, b"\x04host\xc0\x0c", "host.example.com"),
        (15, b"\x00\x0a\x04mail\xc0\x0c", {"preference": 10, "exchange": "mail.example.com"}),
        (16, b"\x05hello\x05world", ["hello", "world"]),
        (
            6,
            b"\x02ns\xc0\x0c\x04mail\xc0\x0c"
            + b"\x00\x00\x00\x01\x00\x00\x1c\x20\x00\x00\x0e\x10\x00\x00\x2a\x30\x00\x00\x0e\x10",
            {
                "mname": "ns.example.com",
                "rname": "mail.example.com",
                "serial": 1,
                "refresh": 7200,
                "retry": 3600,
                "expire": 10800,
                "minimum": 3600,
            },
        ),
        (99, b"\xde\xad\xbe\xef", {"raw_hex": "deadbeef"}),
    ],
)
def test_record_data_is_decoded_per_type(rtype: int, rdata: bytes, expected: object) -> None:
    info, errors = parse_dns(_response(rtype, rdata), _transport())

    assert errors == []
    assert info.answers[0].rdata == expected


@pytest.mark.parametrize(
    "name",
    [
        b"\x01a\xc0\x0c",
        b"\xc0\x20",
        _name([63, 63, 63, 62]),
        b"\x40" + b"a" * 64,
    ],
)
def test_a_broken_name_is_malformed(name: bytes) -> None:
    info, errors = parse_dns(_header() + _question(name), _transport())

    assert [(error.stage, error.type) for error in errors] == [("dns", "malformed")]
    assert info.questions == []
    assert info.partial is True


def test_the_record_limit_is_reported() -> None:
    message = _header(question=65) + b"".join(_question() for _ in range(65))

    info, errors = parse_dns(message, _transport())

    assert [(error.stage, error.type) for error in errors] == [("dns", "limit")]
    assert len(info.questions) == 64


def test_a_cut_answer_is_truncated_not_malformed() -> None:
    message = _response(1, bytes([93, 184, 216, 34]))[:-2]

    info, errors = parse_dns(message, _transport())

    assert [(error.stage, error.type) for error in errors] == [("dns", "truncated")]
    assert info.answers == []
    assert info.partial is True
