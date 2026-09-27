import pytest

from ids.parsers.smtp import parse_smtp


@pytest.mark.parametrize(
    ("text", "command", "argument"),
    [
        ("HELO example.com", "HELO", "example.com"),
        ("EHLO example.com", "EHLO", "example.com"),
        ("ehlo example.com", "EHLO", "example.com"),
        ("MAIL FROM:<alice@example.com>", "MAIL FROM", "<alice@example.com>"),
        ("MAIL FROM: <alice@example.com>", "MAIL FROM", "<alice@example.com>"),
        ("RCPT TO:<bob@example.com>", "RCPT TO", "<bob@example.com>"),
        ("DATA", "DATA", ""),
        ("RSET", "RSET", ""),
        ("NOOP", "NOOP", ""),
        ("QUIT", "QUIT", ""),
        ("VRFY alice", "VRFY", "alice"),
        ("EXPN staff", "EXPN", "staff"),
        ("HELP", "HELP", ""),
        ("AUTH PLAIN", "AUTH", "PLAIN"),
        ("STARTTLS", "STARTTLS", ""),
    ],
)
def test_each_command_is_recognised(text: str, command: str, argument: str) -> None:
    info, errors = parse_smtp((text + "\r\n").encode())

    assert errors == []
    assert info.kind == "command"
    assert info.partial is False
    assert (info.lines[0].command, info.lines[0].argument) == (command, argument)


def test_a_response_line_is_split() -> None:
    info, _ = parse_smtp(b"250 OK\r\n")

    line = info.lines[0]
    assert info.kind == "response"
    assert (line.code, line.separator, line.message) == (250, " ", "OK")


def test_a_multiline_response_is_flagged() -> None:
    info, _ = parse_smtp(b"250-mail.example.com\r\n250-SIZE 10240000\r\n250 HELP\r\n")

    assert info.multiline is True
    assert [line.separator for line in info.lines] == ["-", "-", " "]
    assert [line.code for line in info.lines] == [250, 250, 250]
    assert info.lines[-1].message == "HELP"


def test_data_lines_after_a_response() -> None:
    info, _ = parse_smtp(b"354 End data with <CR><LF>.<CR><LF>\r\nfirst line\r\n.\r\n")

    assert info.kind == "response"
    assert [line.kind for line in info.lines] == ["response", "data", "data"]
    assert [line.text for line in info.lines[1:]] == ["first line", "."]


def test_a_line_that_is_not_a_command_is_data() -> None:
    info, _ = parse_smtp(b"MAIL a@b.c\r\nHello Bob.\r\n")

    assert [line.kind for line in info.lines] == ["data", "data"]


@pytest.mark.parametrize("text", [b"12345 records", b"2502 OK", b"650 not a reply", b"25"])
def test_a_number_without_a_reply_shape_is_data(text: bytes) -> None:
    info, _ = parse_smtp(text + b"\r\n")

    assert info.lines[0].kind == "data"
    assert info.lines[0].code is None


def test_lf_only_is_accepted() -> None:
    info, errors = parse_smtp(b"EHLO example.com\nMAIL FROM:<a@b.c>\n")

    assert errors == []
    assert [line.kind for line in info.lines] == ["command", "command"]
    assert info.lines[1].argument == "<a@b.c>"
    assert info.partial is False


def test_a_partial_line_is_flagged() -> None:
    info, _ = parse_smtp(b"EHLO example.com\r\nMAIL FROM:<a@b.c>")

    assert info.partial is True
    assert [line.kind for line in info.lines] == ["command", "command"]


def test_the_line_limit_is_reported() -> None:
    payload = b"".join(b"NOOP\r\n" for _ in range(1001))

    info, errors = parse_smtp(payload)

    assert [(error.stage, error.type) for error in errors] == [("smtp", "limit")]
    assert len(info.lines) == 1000


def test_bad_bytes_do_not_raise() -> None:
    info, _ = parse_smtp(b"250 caf\xe9\r\n")

    assert info.lines[0].message == "caf\ufffd"
