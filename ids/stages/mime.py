"""Decode Base64 and Quoted-Printable bodies of a MIME message."""

import base64
import quopri
import re
from dataclasses import dataclass, field

BASE64_CHARACTERS = re.compile(rb"[A-Za-z0-9+/=]*")
INVALID_QP_ESCAPE = re.compile(rb"=(?![0-9A-Fa-f]{2}|\r?\n)")
INCOMPLETE_QP_ESCAPE = re.compile(rb"=(?:[0-9A-Fa-f]|\r)?\Z")
TRAILING_WHITESPACE = re.compile(rb"[ \t]+(?=\r?\n)")


@dataclass
class Decoded:
    data: bytes | None
    problems: list[str] = field(default_factory=list)


def decode_base64(data: bytes, complete: bool) -> Decoded:
    """Decode Base64 and keep the longest valid prefix.

    `complete` is false when the message is cut. A short last group is then a cut, not a fault.
    """
    compact = b"".join(data.split())
    if not BASE64_CHARACTERS.fullmatch(compact):
        return Decoded(None, ["invalid Base64 character"])
    body, equals, tail = compact.partition(b"=")
    remainder = len(body) % 4
    problems = []
    if equals:
        padded = remainder in (2, 3) and tail == b"=" * len(tail) and remainder + 1 + len(tail) == 4
        cut_inside_padding = not complete and remainder == 2 and not tail
        if not (padded or cut_inside_padding):
            problems.append("invalid Base64 padding")
    elif remainder == 1 and complete:
        problems.append("invalid Base64 length")
    elif remainder in (2, 3) and complete:
        problems.append("invalid Base64 padding")
    usable = body[:-1] if remainder == 1 else body
    return Decoded(base64.b64decode(usable + b"=" * (-len(usable) % 4)), problems)


def decode_quoted_printable(data: bytes, complete: bool) -> Decoded:
    """Decode Quoted-Printable. `quopri` never raises, so a regex finds the bad escapes."""
    # RFC 2045 section 6.7: a decoder deletes trailing white space. Without this step,
    # "scr= \r\nipt" would stay split in the output and hide "script".
    data = TRAILING_WHITESPACE.sub(b"", data)
    checked = data
    if not complete:
        cut = INCOMPLETE_QP_ESCAPE.search(data, max(0, len(data) - 3))
        if cut:
            checked = data[: cut.start()]
    problems = ["invalid Quoted-Printable escape"] if INVALID_QP_ESCAPE.search(checked) else []
    return Decoded(quopri.decodestring(data), problems)
