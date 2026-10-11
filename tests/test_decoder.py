"""Tests for the decoder."""

import pytest

from ids.config import Config
from ids.enrich import Enricher
from ids.stages.decoder import decode_entities, decode_record, decode_target


@pytest.mark.parametrize(
    ("target", "value", "methods", "problems"),
    [
        ("/search?q=%27%20OR%201%3D1", "/search?q=' OR 1=1", ["form"], []),
        ("/a+b?c+d=e%2Bf", "/a+b?c d=e+f", ["form"], []),
        ("/a%2Fb", "/a/b", ["percent"], []),
        ("/index.html", "/index.html", [], []),
        ("/p?q=%zz", "/p?q=%zz", [], ["invalid percent escape"]),
        ("/p?q=%", "/p?q=%", [], ["invalid percent escape"]),
        ("/p?q=%c0%af", "/p?q=��", ["form"], ["invalid UTF-8"]),
        ("/p?q=%252527", "/p?q=%2527", ["form"], []),
        ("/p%00x", "/p\x00x", ["percent"], []),
        ("/cafÃ©?q=%C3%A9", "/café?q=é", ["form"], []),
        ("/cafÃ©", "/café", ["charset:utf-8"], []),
        ("/€?q=%41", "/€?q=A", ["form"], []),
        ("/café?q=%41", "/café?q=A", ["form"], []),
    ],
    ids=[
        "sql-injection", "plus-in-path-and-query", "encoded-slash", "plain", "bad-escape",
        "lone-percent", "overlong-utf8", "decoded-once", "null-byte", "utf8-read-as-latin1",
        "utf8-only-reread", "hand-written-euro", "hand-written-e-acute",
    ],
)
def test_decode_target(target: str, value: str, methods: list[str], problems: list[str]) -> None:
    result = decode_target(target)

    assert (result.value, result.methods, result.problems) == (value, methods, problems)


@pytest.mark.parametrize(
    ("text", "value", "problems"),
    [
        ("&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>", []),
        ("&LT;&Lt;&NotEqualTilde;", "<\u226a\u2242\u0338", []),
        ("&amp;lt;", "&lt;", []),
        ("&#x41;&#65;&#X41;&#x000041;", "AAAA", []),
        ("&#128;&#x9f;", "\u20ac\u0178", []),
        ("&#1;&#x7f;&#xFFFE;&#x10FFFF;", "\x01\x7f\ufffe\U0010ffff", []),
        ("&#xFFFD;&#x0FFFD;&#65533;", "\ufffd\ufffd\ufffd", []),
        ("&#0;", "\ufffd", ["invalid numeric entity"]),
        ("&#xD800;&#xDFFF;", "\ufffd\ufffd", ["invalid numeric entity"]),
        ("&#x110000;&#9999999;", "\ufffd\ufffd", ["invalid numeric entity"]),
        ("&#0000000060;&#x00003C;&#x000000000000000000003c;", "<<<", []),
        ("&#99999999;&#x1000000;", "\ufffd\ufffd", ["invalid numeric entity"]),
        ("&#" + "0" * 5000 + "60;", "<", []),
        ("&#" + "9" * 5000 + ";", "\ufffd", ["invalid numeric entity"]),
        ("a=1&lt=2", "a=1&lt=2", []),
        ("&amp &lt", "&amp &lt", []),
        ("&notit; &ampx; &unknown; &lT;", "&notit; &ampx; &unknown; &lT;", []),
        ("plain text & more", "plain text & more", []),
        ("&", "&", []),
    ],
    ids=[
        "script-tag", "named-case-and-two-code-points", "decoded-once", "numeric-forms", "windows-1252-range",
        "control-and-noncharacter-kept", "replacement-character-is-no-fault", "zero", "surrogates", "too-large",
        "leading-zeros", "too-many-digits", "very-long-zero-run", "more-digits-than-int-accepts", "no-semicolon-lt", "no-semicolon-amp", "legacy-prefix-and-unknown", "plain", "lone-ampersand",
    ],
)
def test_decode_entities(text: str, value: str, problems: list[str]) -> None:
    result = decode_entities(text)

    assert (result.value, result.problems) == (value, problems)
    assert result.methods == (["html_entity"] if value != text else [])
    result.value.encode("utf-8")


LIMIT = 4096


def _record(payload: bytes, protocol: str = "UNKNOWN", **application: object) -> dict:
    record = {"app_protocol": protocol, "payload_hex": payload.hex(), "payload_len": len(payload)}
    if protocol == "HTTP":
        record["application"] = application
    return record


def _message(body: bytes, content_type: str | None = None, start: bytes = b"POST / HTTP/1.1") -> bytes:
    headers = b"" if content_type is None else b"\r\nContent-Type: " + content_type.encode()
    return start + headers + b"\r\n\r\n" + body


def _fields(result: dict) -> dict[str, tuple]:
    return {item["field"]: (item["value"], item["status"], item["reason"]) for item in result["decoded"]}


def test_a_percent_encoded_target_gives_one_item_and_leaves_the_record_alone() -> None:
    record = _record(b"GET /s?q=%27%20OR%201%3D1 HTTP/1.1\r\n\r\n", "HTTP", target="/s?q=%27%20OR%201%3D1")
    before = dict(record)

    result = decode_record(record, LIMIT)

    assert result["decode_status"] == "ok"
    assert [(i["field"], i["value"], i["methods"]) for i in result["decoded"]] == [
        ("http.target", "/s?q=' OR 1=1", ["form"])
    ]
    assert result["processing_errors"] == []
    assert record == before


def test_a_plain_request_needs_no_decoding() -> None:
    record = _record(b"GET /index.html HTTP/1.1\r\n\r\n", "HTTP", target="/index.html")

    assert decode_record(record, LIMIT) == {"decode_status": "not_applicable", "decoded": [], "processing_errors": []}


@pytest.mark.parametrize(
    ("body", "content_type", "value"),
    [
        (b"q=%26lt%3Bscript%26gt%3B&a=b+c", "application/x-www-form-urlencoded", "q=<script>&a=b c"),
        (b"&lt;b&gt;hi&lt;/b&gt;", "text/html; charset=utf-8", "<b>hi</b>"),
        (b"&lt;b&gt;", None, "<b>"),
        (b"&lt;b&gt;", "Text/Plain", "<b>"),
    ],
    ids=["form-then-entity", "text-html", "no-content-type", "media-type-case"],
)
def test_a_text_body_is_decoded_into_one_item(body: bytes, content_type: str | None, value: str) -> None:
    record = _record(_message(body, content_type), "HTTP", content_type=content_type)

    result = decode_record(record, LIMIT)

    assert _fields(result) == {"http.body": (value, "ok", None)}


@pytest.mark.parametrize(
    ("body", "content_type", "headers"),
    [
        (b"&lt;b&gt;", "application/json", {}),
        (b"&lt;b&gt;", "image/png", {}),
        (b"&lt;b&gt;", "text/html", {"content-encoding": "gzip"}),
        (b"&lt;b&gt;", "text/html", {"content-encoding": ["identity", "br"]}),
    ],
    ids=["json", "image", "gzip", "list-with-brotli"],
)
def test_a_body_that_is_not_text_gets_no_item(body: bytes, content_type: str, headers: dict) -> None:
    record = _record(_message(body, content_type), "HTTP", content_type=content_type, headers=headers)

    assert decode_record(record, LIMIT)["decoded"] == []


@pytest.mark.parametrize(
    ("application", "decoded"),
    [
        ({"headers": {"Content-Encoding": "GZIP"}}, False),
        ({"headers": {"Content-Type": "application/json"}}, False),
        ({"headers": {"CONTENT-TYPE": "text/html"}}, True),
    ],
    ids=["encoding-in-any-case", "type-in-any-case", "text-type-in-any-case"],
)
def test_header_names_are_read_without_regard_to_case(application: dict, decoded: bool) -> None:
    record = _record(_message(b"&lt;"), "HTTP", **application)

    assert bool(decode_record(record, LIMIT)["decoded"]) is decoded


def test_a_single_invalid_sequence_is_named_in_the_singular() -> None:
    result = decode_record(_record(b"hello \xff world, this text is long enough"), LIMIT)

    assert result["decoded"][0]["reason"] == "invalid UTF-8: 1 invalid sequence replaced"


def test_identity_encoding_still_decodes_the_body() -> None:
    record = _record(_message(b"&lt;", "text/html"), "HTTP", content_type="text/html", headers={"content-encoding": "identity"})

    assert _fields(decode_record(record, LIMIT)) == {"http.body": ("<", "ok", None)}


def test_a_body_with_a_fault_of_its_own_is_never_ok() -> None:
    record = _record(_message(b"\xff&lt;", "text/html"), "HTTP", content_type="text/html")

    fields = _fields(decode_record(record, LIMIT))

    assert fields["http.body"] == ("\ufffd<", "partial", "invalid UTF-8 in body")


def test_a_body_whose_only_fault_is_raw_invalid_bytes_is_left_to_the_payload_item() -> None:
    record = _record(_message(b"hello \xff\xfe\x80 world and more text", "text/html"), "HTTP", content_type="text/html")

    result = decode_record(record, LIMIT)

    assert [item["field"] for item in result["decoded"]] == ["payload"]
    assert result["decoded"][0]["status"] == "partial"
    assert result["decoded"][0]["reason"] == "invalid UTF-8: 3 invalid sequences replaced"
    assert result["decode_status"] == "partial"


def test_the_application_protocol_is_compared_without_regard_to_case() -> None:
    record = _record(_message(b"&lt;", "text/html"), "HTTP", content_type="text/html")
    record["app_protocol"] = "Http"

    assert "http.body" in _fields(decode_record(record, LIMIT))


def test_a_http_record_without_application_still_gets_its_body_decoded() -> None:
    record = _record(_message(b"&lt;"), "HTTP")
    del record["application"]

    assert _fields(decode_record(record, LIMIT)) == {"http.body": ("<", "ok", None)}


def test_a_record_that_does_not_say_the_body_is_cut_is_not_marked_cut() -> None:
    complete = _record(_message(b"&lt;"), "HTTP", body_complete=True)
    unknown = _record(_message(b"&lt;"), "HTTP")
    cut = _record(_message(b"&lt;"), "HTTP", body_complete=False)
    null = _record(_message(b"&lt;"), "HTTP", body_complete=None)

    assert _fields(decode_record(complete, LIMIT))["http.body"][1] == "ok"
    assert _fields(decode_record(null, LIMIT))["http.body"][1] == "ok"
    assert _fields(decode_record(unknown, LIMIT))["http.body"][1] == "ok"
    assert _fields(decode_record(cut, LIMIT))["http.body"][2] == "body continues in a later segment"


def test_items_come_in_a_fixed_order() -> None:
    payload = _message("&lt;caf\u00e9".encode(), "text/html", b"GET /a%20b HTTP/1.1")
    record = _record(payload, "HTTP", target="/a%20b", content_type="text/html")

    assert [item["field"] for item in decode_record(record, LIMIT)["decoded"]] == ["http.target", "http.body", "payload"]


@pytest.mark.parametrize(
    ("payload", "status", "reason", "has_value"),
    [
        ("caf\u00e9 au lait".encode(), "ok", None, True),
        (b"hello \xff\xfe world, this text is long enough", "partial", "invalid UTF-8: 2 invalid sequences replaced", True),
        (bytes(range(128, 256)), "partial", "binary payload", False),
        (b"\x00\x01\x02\xff abcd", "partial", "binary payload", False),
        ("ok \ufffd text".encode(), "ok", None, True),
    ],
    ids=["valid-utf8", "few-invalid-bytes", "binary", "control-bytes", "genuine-replacement-character"],
)
def test_payload_text(payload: bytes, status: str, reason: str | None, has_value: bool) -> None:
    result = decode_record(_record(payload), LIMIT)

    (item,) = result["decoded"]
    assert (item["field"], item["status"], item["reason"]) == ("payload", status, reason)
    assert (item["value"] is not None) is has_value


def test_pure_ascii_even_with_control_bytes_and_an_empty_payload_need_no_item() -> None:
    assert decode_record(_record(b"hello world"), LIMIT)["decoded"] == []
    assert decode_record(_record(b""), LIMIT)["decoded"] == []
    assert decode_record(_record(b"\x00\x01\x02\x03 abcd"), LIMIT)["decoded"] == []


def test_a_dns_record_is_skipped() -> None:
    assert decode_record(_record(bytes(range(256)), "DNS"), LIMIT)["decode_status"] == "not_applicable"


def test_a_payload_cut_by_the_pipeline_limit_is_reported_once() -> None:
    record = _record(b"caf\xc3\xa9" * 4)
    record["payload_hex"] = record["payload_hex"][:16]
    record["payload_len"] = 20

    result = decode_record(record, LIMIT)

    assert [e["message"] for e in result["processing_errors"]] == ["payload cut at the payload limit (8 of 20 bytes)"]
    assert result["decoded"][0]["reason"] == "payload cut"


def test_a_payload_that_the_decoder_cuts_itself_is_a_cut_without_a_length() -> None:
    record = {"app_protocol": "UNKNOWN", "payload_hex": ("c3a9" * 100)}

    result = decode_record(record, 3)

    assert [e["message"] for e in result["processing_errors"]] == ["payload cut at the payload limit (3 bytes)"]
    (item,) = result["decoded"]
    assert item["reason"] == "payload cut"
    assert item["value"] == "\u00e9"


def test_a_character_that_the_limit_splits_is_not_counted_as_invalid() -> None:
    record = _record(b"ab\xc3\xa9")

    result = decode_record(record, 3)

    assert result["decoded"][0]["reason"] == "payload cut"


def test_a_body_character_that_the_cut_splits_is_not_counted_as_invalid() -> None:
    payload = _message(b"&lt;caf\xc3", "text/html")
    record = _record(payload, "HTTP", content_type="text/html")
    record["payload_len"] = len(payload) + 1

    fields = _fields(decode_record(record, LIMIT))

    assert fields["http.body"] == ("<caf", "partial", "payload cut")


def test_the_preview_is_used_when_there_is_no_payload_hex() -> None:
    record = {"app_protocol": "UNKNOWN", "payload_preview": "c3a9", "payload_len": 100}

    result = decode_record(record, LIMIT)

    assert [e["message"] for e in result["processing_errors"]] == ["payload cut to the preview (2 of 100 bytes)"]
    assert result["decode_status"] == "partial"


@pytest.mark.parametrize("payload_hex", ["41 42", "4142\n", "414", "zz", "\uff14\uff11"])
def test_text_that_is_not_hex_is_not_a_cut(payload_hex: str) -> None:
    result = decode_record({"app_protocol": "UNKNOWN", "payload_hex": payload_hex, "payload_len": 9}, LIMIT)

    assert [(i["field"], i["reason"]) for i in result["decoded"]] == [("payload", "payload is not hex")]
    assert result["processing_errors"] == []


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"app_protocol": "HTTP"},
        {"app_protocol": "HTTP", "application": {"target": "/a"}},
        {"app_protocol": 5, "application": [], "payload_hex": 7, "payload_preview": None, "payload_len": True},
        {"app_protocol": "HTTP", "application": {"target": 5, "content_type": [], "headers": []}, "payload_hex": ""},
    ],
)
def test_a_record_without_bytes_or_with_wrong_types_gives_no_error(record: dict) -> None:
    result = decode_record(record, LIMIT)

    assert result["decoded"] == []
    assert result["processing_errors"] == []


def test_a_target_longer_than_the_limit_is_cut_and_says_so() -> None:
    record = {"app_protocol": "HTTP", "application": {"target": "/" + "%41" * 50}}

    (item,) = decode_record(record, 10)["decoded"]

    assert len(item["value"]) == 10
    assert item["reason"] == "value cut at 10 characters"


def test_the_enricher_runs_the_real_decoder() -> None:
    record = _record(b"GET /a%20b HTTP/1.1\r\n\r\n", "HTTP", target="/a%20b")

    output, _ = Enricher(Config(None, None, "out.jsonl", "keep", None)).process(record)

    assert output["decode_status"] == "ok"
    assert [item["field"] for item in output["decoded"]] == ["http.target"]


MIME_MESSAGE = b"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n.\r\n"


def _mime_record(payload: bytes = MIME_MESSAGE, protocol: str | None = "UNKNOWN", **record: object) -> dict:
    base = {"transport": {"protocol": "TCP"}, "payload_hex": payload.hex(), "payload_len": len(payload)}
    if protocol is not None:
        base["app_protocol"] = protocol
    return {**base, **record}


@pytest.mark.parametrize(
    ("record", "fields"),
    [
        (_mime_record(), ["mime.body"]),
        (_mime_record(protocol="SMTP"), ["mime.body"]),
        (_mime_record(protocol=None), ["mime.body"]),
        (_mime_record(protocol="tcp-garbage"), ["mime.body"]),
        (_mime_record(transport={"protocol": "tcp"}), ["mime.body"]),
        (_mime_record(protocol="HTTP"), []),
        (_mime_record(protocol="DNS"), []),
        (_mime_record(transport={"protocol": "UDP"}), []),
        (_mime_record(transport=None), []),
        (_mime_record(payload_hex="not hex"), ["payload"]),
    ],
    ids=["unknown", "smtp", "missing-protocol", "other-protocol", "lower-case-tcp", "http", "dns", "udp",
         "missing-transport", "not-hex"],
)
def test_mime_runs_for_a_tcp_record_that_is_not_http_or_dns(record: dict, fields: list[str]) -> None:
    result = decode_record(record, LIMIT)

    assert [item["field"] for item in result["decoded"]] == fields


def test_a_cut_after_the_end_marker_does_not_touch_the_message() -> None:
    record = _mime_record(MIME_MESSAGE + b"QUIT\r\n" * 10)

    result = decode_record(record, len(MIME_MESSAGE) + 3)

    assert [(i["field"], i["value"], i["status"]) for i in result["decoded"]] == [("mime.body", "Hello", "ok")]
    assert [e["type"] for e in result["processing_errors"]] == ["limit"]


def test_a_failed_item_and_an_ok_item_make_the_record_partial() -> None:
    bad = b"--XX\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!\r\n"
    good = b"--XX\r\nContent-Transfer-Encoding: base64\r\n\r\nSGk=\r\n--XX--"
    message = b"Content-Type: multipart/mixed; boundary=XX\r\n\r\n" + bad + good + b"\r\n.\r\n"

    result = decode_record(_mime_record(message), LIMIT)

    assert [(i["field"], i["status"], i["value"]) for i in result["decoded"]] == [
        ("mime.part[1]", "failed", None),
        ("mime.part[2]", "ok", "Hi"),
    ]
    assert result["decode_status"] == "partial"


def test_a_record_with_only_failed_items_is_failed() -> None:
    message = b"Content-Transfer-Encoding: base64\r\n\r\n!!!\r\n.\r\n"

    assert decode_record(_mime_record(message), LIMIT)["decode_status"] == "failed"


def test_mime_items_come_before_the_payload_item() -> None:
    message = b"Content-Transfer-Encoding: quoted-printable\r\n\r\nabc\xffdef\r\n.\r\n"

    result = decode_record(_mime_record(message), LIMIT)

    assert [item["field"] for item in result["decoded"]] == ["mime.body", "payload"]

