"""Tests for the MIME decoder."""

import base64
import time

import pytest

from ids.stages.mime import MAX_MIME_NESTING, MAX_MIME_PARTS, decode_base64, decode_mime, decode_quoted_printable

END = b"\r\n.\r\n"
BASE64_HEADER = b"Content-Transfer-Encoding: base64\r\n\r\n"
QP_HEADER = b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"


def part(headers: bytes, body: bytes) -> bytes:
    return b"--XX\r\n" + headers + b"\r\n\r\n" + body + b"\r\n"


def multipart(*parts: bytes) -> bytes:
    return b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" + b"".join(parts) + b"--XX--" + END


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


@pytest.mark.parametrize(
    ("message", "value", "methods", "problems"),
    [
        (
            b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            + base64.b64encode("héllo".encode()) + END,
            "héllo", ["base64", "charset:utf-8"], [],
        ),
        (
            b"Content-Type: text/plain; charset=ISO-8859-1\r\n" + QP_HEADER + b"caf=E9" + END,
            "café\r\n", ["quoted-printable", "charset:iso-8859-1"], [],
        ),
        (b"Content-Type: text/plain; charset=latin-1\r\n" + QP_HEADER + b"caf=E9" + END,
         "café\r\n", ["quoted-printable", "charset:iso-8859-1"], []),
        (QP_HEADER + b"a=3Db" + END, "a=b\r\n", ["quoted-printable"], []),
        (QP_HEADER + b"caf=C3=A9" + END, "café\r\n", ["quoted-printable", "charset:utf-8"], []),
        (b"content-transfer-encoding:  BASE64 \r\n\r\nSGVsbG8=" + END, "Hello", ["base64"], []),
        (b"Content-Transfer-Encoding: base64\n\nSGVs\nbG8=\r\n.\r\n", "Hello", ["base64"], []),
    ],
    ids=["base64-utf8", "qp-iso-8859-1", "latin-1-label", "no-charset", "no-charset-utf8-bytes", "header-spelling", "bare-lf"],
)
def test_mime_single_part_decodes(message: bytes, value: str, methods: list[str], problems: list[str]) -> None:
    items = decode_mime(message, cut=False)

    assert [(i.field_name, i.value, i.methods, i.problems, i.failed) for i in items] == [
        ("mime.body", value, methods, problems, False)
    ]


def test_mime_framing_removes_dot_stuffing_and_data_after_the_dot() -> None:
    message = QP_HEADER + b"..hidden\r\nmid..dle\r\n.\r\nQUIT\r\n.\r\n"

    items = decode_mime(message, cut=False)

    assert [(i.value, i.problems) for i in items] == [(".hidden\r\nmid..dle\r\n", [])]


@pytest.mark.parametrize(
    ("message", "cut", "value", "problems"),
    [
        (BASE64_HEADER + b"SGVsbG8=\r\n", False, "Hello", ["message continues in a later segment"]),
        (BASE64_HEADER + b"SGVsbG8=\r\n", True, "Hello", ["payload cut"]),
        (BASE64_HEADER + b"SGVsb", True, "Hel", ["payload cut"]),
        (BASE64_HEADER + b"SGVsbG8=" + END + b"QUIT\r\n", True, "Hello", []),
        (BASE64_HEADER + base64.b64encode(b"a\xc3"), True, "a", ["payload cut"]),
        (QP_HEADER + b"hi\r\n.\n", False, "hi\r\n.\n", ["message continues in a later segment"]),
    ],
    ids=["no-marker", "cut", "cut-in-group", "cut-after-marker", "cut-inside-character", "lf-marker-not-accepted"],
)
def test_mime_incomplete_message_gives_one_reason(message: bytes, cut: bool, value: str, problems: list[str]) -> None:
    items = decode_mime(message, cut=cut)

    assert [(i.value, i.problems) for i in items] == [(value, problems)]


@pytest.mark.parametrize(
    "message",
    [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"Hello Bob.\r\n.\r\n",
        b"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGk=" + END,
        BASE64_HEADER,
        b"Content-Transfer-Encoding: base64\r\n",
        b"Content-Transfer-Encoding: 7bit\r\n\r\nhello" + END,
        b"Content-Transfer-Encoding: 8bit\r\n\r\nhello" + END,
        b"Content-Transfer-Encoding: binary\r\n\r\nhello" + END,
        b"Content-Transfer-Encoding: x-custom\r\n\r\nhello" + END,
        b"Content-Type: image/png\r\n" + BASE64_HEADER + b"iVBORw0K" + END,
    ],
    ids=[
        "http", "plain-text", "leading-blank-line", "no-body", "no-blank-line", "7bit", "8bit", "binary",
        "unknown-encoding", "image",
    ],
)
def test_mime_gives_no_item(message: bytes) -> None:
    assert decode_mime(message, cut=False) == []


def test_mime_multipart_numbers_every_part_and_decodes_soft_breaks() -> None:
    message = multipart(
        part(b"Content-Type: image/png\r\n" + b"Content-Transfer-Encoding: base64", b"iVBORw0K"),
        part(b"Content-Transfer-Encoding: quoted-printable", b"text="),
        part(b"Content-Transfer-Encoding: quoted-printable", b"a=3Db"),
        part(b"Content-Transfer-Encoding: quoted-printable", b"spaced= \t"),
    )

    items = decode_mime(message, cut=False)

    assert [(i.field_name, i.value, i.problems) for i in items] == [
        ("mime.part[2]", "text", []),
        ("mime.part[3]", "a=b", []),
        ("mime.part[4]", "spaced", []),
    ]


def test_mime_multipart_nested_parts_are_leaves() -> None:
    inner = b"Content-Type: multipart/alternative; boundary=YY\r\n\r\n--YY\r\n" + QP_HEADER + b"one\r\n--YY--\r\n"
    message = b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\n" + inner
    message += b"--XX\r\n" + QP_HEADER + b"two\r\n--XX--" + END

    items = decode_mime(message, cut=False)

    assert [(i.field_name, i.value) for i in items] == [("mime.part[1]", "one"), ("mime.part[2]", "two")]


@pytest.mark.parametrize(
    ("depth", "names"),
    [(MAX_MIME_NESTING, []), (MAX_MIME_NESTING + 1, ["mime.body"])],
    ids=["at-the-cap", "above-the-cap"],
)
def test_mime_nesting_cap(depth: int, names: list[str]) -> None:
    message = b"".join(
        b"Content-Type: multipart/mixed; boundary=B%d\r\n\r\n--B%d\r\n" % (level, level) for level in range(depth)
    )

    items = decode_mime(message, cut=False)

    assert [i.field_name for i in items] == names
    assert all((i.value, i.problems) == (None, ["too many nested parts"]) for i in items)


def test_mime_nesting_cap_counts_only_content_type_header_lines() -> None:
    notes = b"".join(b"X-Note: content-type: multipart/mixed\r\n" for _ in range(MAX_MIME_NESTING + 8))

    items = decode_mime(notes + BASE64_HEADER + b"SGk=" + END, cut=False)

    assert [i.value for i in items] == ["Hi"]


def test_mime_part_cap_adds_a_partial_item() -> None:
    one = part(b"Content-Transfer-Encoding: base64", b"SGk=")
    items = decode_mime(multipart(*[one] * (MAX_MIME_PARTS + 4)), cut=False)

    assert len(items) == MAX_MIME_PARTS + 1
    assert items[-1].field_name == f"mime.part[{MAX_MIME_PARTS + 1}]"
    assert (items[-1].value, items[-1].problems) == (None, [f"more than {MAX_MIME_PARTS} parts"])
    assert all(i.problems == [] for i in items[:-1])


@pytest.mark.parametrize(
    ("charset", "body", "value", "problems"),
    [
        ("zlib", b"caf=C3=A9", "café\r\n", ["unsupported charset"]),
        ("unicode_escape", b"=5Cud800", "\\ud800\r\n", ["unsupported charset"]),
        ("", b"caf=C3=A9", "café\r\n", []),
        ("utf-8", b"a=FFb", "a\ufffdb\r\n", ["invalid UTF-8: 1 invalid sequence replaced"]),
        ("us-ascii", b"a=FF=FEb", "a\ufffd\ufffdb\r\n", ["invalid US-ASCII: 2 invalid sequences replaced"]),
        ("us-ascii", b"=EF=BF=BD", "\ufffd\ufffd\ufffd\r\n", ["invalid US-ASCII: 3 invalid sequences replaced"]),
    ],
    ids=["unknown-codec", "escape-codec", "empty-charset", "invalid-utf8", "invalid-ascii", "utf8-replacement-bytes-in-ascii"],
)
def test_mime_charset(charset: str, body: bytes, value: str, problems: list[str]) -> None:
    message = b"Content-Type: text/plain; charset=" + charset.encode() + b"\r\n" + QP_HEADER + body + END

    items = decode_mime(message, cut=False)

    assert [(i.value, i.problems) for i in items] == [(value, problems)]


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        (b"text/plain;a*", [("mime.body", "Hi", [])]),
        (b"text/plain; charset*=", [("mime.body", "Hi", [])]),
        (b"multipart/mixed; boundary*", []),
        (b"multipart/mixed; boundary*=undefined''x", [("mime.body", None, ["malformed MIME headers"])]),
        (b"multipart/mixed; boundary*=idna''x", [("mime.body", None, ["malformed MIME headers"])]),
    ],
    ids=["star-parameter", "empty-extended-charset", "star-boundary", "undefined-codec", "idna-codec"],
)
def test_mime_malformed_content_type(content_type: bytes, expected: list[tuple]) -> None:
    message = b"Content-Type: " + content_type + b"\r\n" + BASE64_HEADER + b"SGk=" + END

    items = decode_mime(message, cut=False)

    assert [(i.field_name, i.value, i.problems) for i in items] == expected


def test_mime_failed_part_names_only_its_coding_fault() -> None:
    items = decode_mime(BASE64_HEADER + b"!!!", cut=True)

    assert [(i.value, i.problems, i.failed) for i in items] == [(None, ["invalid Base64 character"], True)]


def test_mime_large_header_line_is_fast() -> None:
    message = b"X-A: " + b"a" * 5_000_000 + b"\r\n" + BASE64_HEADER + b"SGk=" + END
    started = time.perf_counter()

    items = decode_mime(message, cut=False)

    assert [i.value for i in items] == ["Hi"]
    assert time.perf_counter() - started < 1.0
