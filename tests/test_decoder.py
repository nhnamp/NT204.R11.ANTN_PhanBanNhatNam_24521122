"""Tests for the decoder."""

import pytest

from ids.stages.decoder import decode_entities, decode_target


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
