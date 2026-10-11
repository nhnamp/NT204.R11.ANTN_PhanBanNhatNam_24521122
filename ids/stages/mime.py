"""Decode the Base64 and Quoted-Printable text parts of a MIME message."""

import base64
import codecs
import quopri
import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import Parser
from itertools import islice

MAX_MIME_PARTS = 16
MAX_MIME_NESTING = 32
REPLACEMENT = "\ufffd"
SMTP_END = b"\r\n.\r\n"
DOT_STUFFING = re.compile(rb"^\.\.", re.MULTILINE)
MULTIPART_TYPE = re.compile(r"^content-type:\s*multipart/", re.IGNORECASE | re.MULTILINE)
# Label of Content-Type -> (name for the `charset:` method, codec). A short whitelist, because
# codecs.lookup accepts names such as "zlib" and "unicode_escape" that must never decode text.
CHARSETS = {
    "us-ascii": ("us-ascii", "ascii"),
    "ascii": ("us-ascii", "ascii"),
    "utf-8": ("utf-8", "utf-8"),
    "iso-8859-1": ("iso-8859-1", "latin-1"),
    "latin-1": ("iso-8859-1", "latin-1"),
    "iso-8859-15": ("iso-8859-15", "iso-8859-15"),
    "windows-1252": ("windows-1252", "cp1252"),
}
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


ENCODINGS = {"base64": decode_base64, "quoted-printable": decode_quoted_printable}


@dataclass
class MimeItem:
    field_name: str
    value: str | None
    methods: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    failed: bool = False


def decode_text(data: bytes, codec: str = "utf-8", final: bool = True) -> tuple[str, int]:
    """Decode text. Without `final`, an incomplete character at the end is held back, not counted."""
    text = codecs.getincrementaldecoder(codec)("replace").decode(data, final=final)
    invalid = text.count(REPLACEMENT)
    if codec == "utf-8":
        # A genuine U+FFFD in the input is valid text. Other codecs spell it with three characters.
        invalid -= data.count(b"\xef\xbf\xbd")
    return text, max(invalid, 0)


def frame_message(data: bytes) -> tuple[bytes, bool]:
    """Cut at the first end marker and remove dot-stuffing. The flag says that the marker was found.

    Dot-stuffing turns every body line "." into "..", so the first marker is the real end. The kept
    bytes include the line end before the marker.
    """
    end = data.find(SMTP_END)
    message = data if end == -1 else data[: end + 2]
    return DOT_STUFFING.sub(b".", message), end != -1


def decode_mime(data: bytes, cut: bool) -> list[MimeItem]:
    """Decode the text parts of one SMTP message. A payload that is not a MIME message gives no item."""
    try:
        return _decode_mime(data, cut)
    except UnicodeError:
        # The email package raises it for a header such as "boundary*=undefined''x", where the
        # RFC 2231 charset names a codec that cannot decode text. The decoder must not raise.
        return [MimeItem("mime.body", None, problems=["malformed MIME headers"])]


def _decode_mime(data: bytes, cut: bool) -> list[MimeItem]:
    message, complete = frame_message(data)
    # The text parser on latin-1 text keeps every byte. BytesParser re-decodes an 8-bit body
    # with the charset and "replace" in get_payload(), which loses the original bytes.
    # The compat32 policy is deliberate: the default policy raises IndexError on a header such as
    # "Content-Type: text/plain;a*".
    text = message.decode("latin-1")
    headers = Parser(policy=policy.compat32).parsestr(text, headersonly=True)
    if "Content-Transfer-Encoding" not in headers and headers.get_content_maintype() != "multipart":
        return []
    # The parser recurses once per nested multipart part, so the depth is capped before the parse.
    if len(MULTIPART_TYPE.findall(text)) > MAX_MIME_NESTING:
        return [MimeItem("mime.body", None, problems=["too many nested parts"])]
    root = Parser(policy=policy.compat32).parsestr(text)
    reason = None
    if not complete:
        reason = "payload cut" if cut else "message continues in a later segment"
    multipart = root.is_multipart()
    leaves = islice((part for part in root.walk() if not part.is_multipart()), MAX_MIME_PARTS + 1)
    items = []
    for number, leaf in enumerate(leaves, start=1):
        name = f"mime.part[{number}]" if multipart else "mime.body"
        if number > MAX_MIME_PARTS:
            items.append(MimeItem(name, None, problems=[f"more than {MAX_MIME_PARTS} parts"]))
            break
        item = _leaf_item(leaf, name, complete, reason)
        if item is not None:
            items.append(item)
    return items


def _leaf_item(leaf: Message, name: str, complete: bool, reason: str | None) -> MimeItem | None:
    encoding = str(leaf.get("Content-Transfer-Encoding", "")).strip().lower()
    if encoding not in ENCODINGS or leaf.get_content_maintype() != "text":
        return None
    body = leaf.get_payload().encode("latin-1")
    if encoding == "quoted-printable" and body.rstrip(b" \t").endswith(b"="):
        # The parser gives the line end before a boundary to the delimiter, so a soft break at the
        # end of a part arrives as a bare "=". The soft break consumes the appended line end.
        body += b"\r\n"
    decoded = ENCODINGS[encoding](body, complete)
    if decoded.data is None:
        return MimeItem(name, None, problems=decoded.problems, failed=True)
    if not decoded.data and not decoded.problems:
        return None
    problems = list(decoded.problems)
    label = leaf.get_content_charset() or "utf-8"
    if label not in CHARSETS:
        problems.append("unsupported charset")
        label = "utf-8"
    charset, codec = CHARSETS[label]
    text, invalid = decode_text(decoded.data, codec, final=complete)
    if invalid:
        problems.append(f"invalid {charset.upper()}: {invalid} invalid sequence{'' if invalid == 1 else 's'} replaced")
    if reason:
        problems.append(reason)
    methods = [encoding] if decoded.data.isascii() else [encoding, f"charset:{charset}"]
    return MimeItem(name, text, methods, problems)
