"""Tests for the decoder."""

import pytest

from ids.stages.decoder import decode_target


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
