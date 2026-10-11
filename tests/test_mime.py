"""Tests for the MIME decoder."""

import pytest

from ids.stages.mime import decode_base64, decode_quoted_printable


@pytest.mark.parametrize(
    "encoded",
    [b"SGVsbG8=", b"SGVs\r\nbG8=\r\n", b" S G V s\tbG8= "],
    ids=["plain", "wrapped-lines", "white-space"],
)
def test_base64_decodes(encoded: bytes) -> None:
    result = decode_base64(encoded, complete=True)

    assert (result.data, result.problems) == (b"Hello", [])


@pytest.mark.parametrize(
    "encoded",
    [b"!!!", b"SGk\x80=", b"SGk=!", b"SGk.\r\n"],
    ids=["no-valid-character", "high-byte", "after-padding", "dot-terminator"],
)
def test_base64_bad_character_fails(encoded: bytes) -> None:
    result = decode_base64(encoded, complete=True)

    assert (result.data, result.problems) == (None, ["invalid Base64 character"])


@pytest.mark.parametrize(
    ("encoded", "data", "problem"),
    [
        (b"SGk=SGk=", b"Hi", "invalid Base64 padding"),
        (b"SG=A", b"H", "invalid Base64 padding"),
        (b"SGk==", b"Hi", "invalid Base64 padding"),
        (b"SGVs====", b"Hel", "invalid Base64 padding"),
        (b"SGVsb===", b"Hel", "invalid Base64 padding"),
        (b"SGVsbG=", b"Hell", "invalid Base64 padding"),
        (b"SGVsbG8", b"Hello", "invalid Base64 padding"),
        (b"SGVsb", b"Hel", "invalid Base64 length"),
    ],
    ids=[
        "data-after-padding", "data-after-short-padding", "excess-padding", "padding-after-full-group",
        "padding-after-one-character", "half-padding", "missing-padding", "length-one-more",
    ],
)
def test_base64_keeps_valid_prefix(encoded: bytes, data: bytes, problem: str) -> None:
    result = decode_base64(encoded, complete=True)

    assert (result.data, result.problems) == (data, [problem])


@pytest.mark.parametrize("encoded", [b"SGVs=", b"SGVsb=", b"SGk=SGk="], ids=["full-group", "one-character", "data-after"])
def test_base64_misplaced_padding_is_a_fault_when_cut(encoded: bytes) -> None:
    result = decode_base64(encoded, complete=False)

    assert result.problems == ["invalid Base64 padding"]


@pytest.mark.parametrize(
    ("encoded", "data"),
    [(b"SGVsb", b"Hel"), (b"SGVsbG", b"Hell"), (b"SGVsbG=", b"Hell"), (b"SGVsbG8", b"Hello")],
    ids=["length-one-more", "two-characters", "half-padding", "three-characters"],
)
def test_base64_cut_is_not_a_fault(encoded: bytes, data: bytes) -> None:
    result = decode_base64(encoded, complete=False)

    assert (result.data, result.problems) == (data, [])


@pytest.mark.parametrize(
    ("encoded", "data"),
    [
        (b"a=3Db", b"a=b"),
        (b"a=3db", b"a=b"),
        (b"caf=C3=A9", b"caf\xc3\xa9"),
        (b"soft=\r\nbreak", b"softbreak"),
        (b"soft=\nbreak", b"softbreak"),
        (b"line\r\nline\n", b"line\r\nline\n"),
        (b"scr= \r\nipt", b"script"),
        (b"scr=\t\nipt", b"script"),
        (b"trailing \t\r\nspace", b"trailing\r\nspace"),
    ],
    ids=[
        "hex-escape", "lower-case-hex", "utf8-bytes", "soft-break-crlf", "soft-break-lf", "line-ends-kept",
        "space-after-soft-break", "tab-after-soft-break", "trailing-white-space-deleted",
    ],
)
def test_quoted_printable_decodes(encoded: bytes, data: bytes) -> None:
    result = decode_quoted_printable(encoded, complete=True)

    assert (result.data, result.problems) == (data, [])


@pytest.mark.parametrize(
    "encoded",
    [b"bad=ZZ", b"x=", b"x=4", b"x=\r", b"x= y"],
    ids=["not-hex", "trailing-equals", "one-hex-digit", "lone-cr", "space-inside-line"],
)
def test_quoted_printable_bad_escape_is_partial(encoded: bytes) -> None:
    result = decode_quoted_printable(encoded, complete=True)

    assert result.problems == ["invalid Quoted-Printable escape"]


@pytest.mark.parametrize("encoded", [b"x=", b"x=4", b"x=\r"], ids=["equals", "one-hex-digit", "cr"])
def test_quoted_printable_cut_escape_is_not_a_fault(encoded: bytes) -> None:
    result = decode_quoted_printable(encoded, complete=False)

    assert result.problems == []


def test_quoted_printable_cut_does_not_hide_an_earlier_fault() -> None:
    result = decode_quoted_printable(b"bad=ZZ and a cut=4", complete=False)

    assert result.problems == ["invalid Quoted-Printable escape"]
