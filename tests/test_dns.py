"""Tests for the shared DNS name reader."""

import pytest

from ids.parsers.dns import read_name


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
