"""Tests for the HTTP parser."""

from ids.events import HttpInfo
from ids.parsers.http import parse_http

GET = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: NT204/1.0\r\n"
    b"\r\n"
)
POST_BODY = b"user=nt204"
POST = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: 10\r\n"
    b"\r\n"
    + POST_BODY
)
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"Server: NT204\r\n"
    b"\r\n"
    b"hello"
)


def test_a_get_request_is_parsed() -> None:
    info, errors = parse_http(GET)

    assert errors == []
    assert info == HttpInfo(
        kind="request",
        version="HTTP/1.1",
        headers={"host": "example.com", "user-agent": "NT204/1.0"},
        body_len=0,
        body_preview="",
        body_complete=True,
        partial=False,
        method="GET",
        target="/index.html",
        host="example.com",
    )


def test_a_repeated_header_becomes_a_list() -> None:
    info, _ = parse_http(b"GET / HTTP/1.1\r\nCookie: a=1\r\nCookie: b=2\r\n\r\n")

    assert info.headers["cookie"] == ["a=1", "b=2"]


def test_a_post_body_is_measured() -> None:
    info, errors = parse_http(POST)

    assert errors == []
    assert (info.kind, info.method, info.target) == ("request", "POST", "/login")
    assert (info.content_length, info.content_type) == (10, "application/x-www-form-urlencoded")
    assert (info.body_len, info.body_preview, info.body_complete) == (10, "user=nt204", True)


def test_a_short_body_is_not_complete() -> None:
    info, _ = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nshort")

    assert (info.body_len, info.body_complete) == (5, False)


def test_a_response_is_parsed() -> None:
    info, errors = parse_http(RESPONSE)

    assert errors == []
    assert info == HttpInfo(
        kind="response",
        version="HTTP/1.1",
        headers={"content-type": "text/plain", "content-length": "5", "server": "NT204"},
        body_len=5,
        body_preview="hello",
        body_complete=True,
        partial=False,
        status_code=200,
        reason="OK",
        content_length=5,
        content_type="text/plain",
    )


def test_an_unterminated_head_is_partial() -> None:
    info, errors = parse_http(b"GET / HTTP/1.1\r\nHost: example.com")

    assert errors == []
    assert info.partial is True
    assert info.host == "example.com"
    assert info.body_len == 0


def test_the_header_line_limit_is_reported() -> None:
    payload = b"GET / HTTP/1.1\r\n" + b"".join(b"X-%d: v\r\n" % index for index in range(200))

    info, errors = parse_http(payload)

    assert [(error.stage, error.type) for error in errors] == [("http", "limit")]
    assert len(info.headers) == 100


def test_the_header_size_limit_is_reported() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: " + b"a" * 9000 + b"\r\n\r\n"

    _, errors = parse_http(payload)

    assert [(error.stage, error.type) for error in errors] == [("http", "limit")]


def test_bad_bytes_do_not_raise() -> None:
    payload = b"GET /caf\xe9 HTTP/1.1\r\nHost: example.com\r\nX: \xff\xfe\r\n\r\nbody \xff\xfe"

    info, _ = parse_http(payload)

    assert info.target == "/café"
    assert info.headers["x"] == "ÿþ"
    assert "\ufffd" in info.body_preview


def test_a_non_ascii_digit_is_not_a_number() -> None:
    request, _ = parse_http(b"POST / HTTP/1.1\r\nContent-Length: 1\xb2\r\n\r\nx")
    response, _ = parse_http(b"HTTP/1.1 200\xb2 OK\r\n\r\n")

    assert request.content_length is None
    assert response.status_code is None
