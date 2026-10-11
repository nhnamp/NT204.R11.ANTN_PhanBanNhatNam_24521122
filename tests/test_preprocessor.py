"""Tests for record validation and the flow fields of the normalized view."""

import time

import pytest

from ids.contract import empty_normalized
from ids.stages.preprocessor import preprocess_record

TIMESTAMP = 1758441600.0


@pytest.fixture
def local_zone_is_not_utc(monkeypatch: pytest.MonkeyPatch):
    """Make a local-time reading visible: a naive time must still count as UTC."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is not available")
    monkeypatch.setenv("TZ", "Asia/Ho_Chi_Minh")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


def _record(**changes: object) -> dict:
    record = {
        "timestamp": TIMESTAMP,
        "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "frag_offset": 0},
        "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80},
        "status": "ok",
        "errors": [],
    }
    record.update(changes)
    return {key: value for key, value in record.items() if value is not ...}


def _with(part: str, **changes: object) -> dict:
    return _record(**{part: {**_record()[part], **changes}})


@pytest.mark.parametrize(
    ("record", "status", "action", "reason"),
    [
        (_record(), "valid", "keep", None),
        (_record(status=...), "valid", "keep", None),
        (_record(errors=...), "valid", "keep", None),
        (_with("transport", protocol="udp"), "valid", "keep", None),
        (_with("transport", src_port=0), "valid", "keep", None),
        (_record(timestamp=0), "valid", "keep", None),
        (_record(timestamp=4_102_444_800), "valid", "keep", None),
        (_with("network", frag_offset=True), "valid", "keep", None),
        (_record(status="partial"), "partial", "keep", "packet status is partial"),
        (_record(status="weird"), "partial", "keep", "packet status is weird"),
        (_record(status=5), "partial", "keep", "packet status is not text"),
        (_record(transport=None, network=None), "partial", "skip_flow", "no network layer; no transport layer"),
        (_with("transport", protocol="ICMP"), "partial", "skip_flow", "protocol ICMP is not tracked"),
        (_with("transport", protocol=None), "partial", "skip_flow", "protocol is missing or not text"),
        (_with("transport", protocol=6), "partial", "skip_flow", "protocol is missing or not text"),
        (_with("network", frag_offset=8), "partial", "skip_flow", "non-first fragment"),
        (
            _record(errors=[{"stage": "network", "type": "fragment"}], transport=None),
            "partial", "skip_flow", "non-first fragment; no transport layer",
        ),
        (_with("transport", dst_port=70000), "partial", "skip_flow", "port is missing or out of range"),
        (_with("network", dst_ip="fe80::1%eth0"), "partial", "skip_flow", "address is missing or invalid"),
        (_record(timestamp=...), "invalid", "skip_flow", "timestamp is missing or unusable"),
        (["not", "an", "object"], "invalid", "skip_flow", "record is not an object"),
    ],
    ids=[
        "valid", "no-status", "no-errors", "lower-case-protocol", "port-zero", "epoch-zero", "last-second", "bool-offset",
        "base-partial", "base-unlisted-text", "base-unlisted-number",
        "no-layers", "icmp", "protocol-missing", "protocol-number", "fragment-offset", "fragment-error",
        "port-range", "ip-zone", "no-timestamp", "not-an-object",
    ],
)
def test_validation(record: dict, status: str, action: str, reason: str | None) -> None:
    result = preprocess_record(record)

    assert (result["preprocess_status"], result["processing_action"], result["reason"]) == (status, action, reason)


@pytest.mark.parametrize(
    "timestamp",
    [True, "yesterday", "", float("nan"), float("inf"), 1e300, 10**400, -1, 4_102_444_801, "9999-12-31T23:59:59", [1.0]],
    ids=[
        "bool", "text", "empty", "nan", "infinity", "huge-float", "huge-int",
        "negative", "after-2100", "year-9999", "list",
    ],
)
def test_an_unusable_timestamp_makes_the_record_invalid(timestamp: object) -> None:
    result = preprocess_record(_record(timestamp=timestamp, timestamp_iso="2025-09-21T08:00:00+00:00"))

    assert (result["preprocess_status"], result["processing_action"]) == ("invalid", "skip_flow")
    assert result["normalized"]["timestamp"] is None


@pytest.mark.parametrize(
    ("changes", "seconds"),
    [
        ({"timestamp": TIMESTAMP}, TIMESTAMP),
        ({"timestamp": 1758441600}, TIMESTAMP),
        ({"timestamp": "2025-09-21T08:00:00"}, TIMESTAMP),
        ({"timestamp": "2025-09-21T08:00:00Z"}, TIMESTAMP),
        ({"timestamp": "2025-09-21T15:00:00+07:00"}, TIMESTAMP),
        ({"timestamp": None, "timestamp_iso": "2025-09-21T08:00:00"}, TIMESTAMP),
    ],
    ids=["float", "int", "naive-iso-is-utc", "z-suffix", "offset", "iso-field-when-timestamp-missing"],
)
def test_timestamp_forms_give_one_instant(local_zone_is_not_utc: None, changes: dict, seconds: float) -> None:
    normalized = preprocess_record(_record(**changes))["normalized"]

    assert normalized["timestamp"] == seconds
    assert normalized["timestamp_iso"] == "2025-09-21T08:00:00+00:00"


@pytest.mark.parametrize(
    ("src_port", "dst_port", "expected"),
    [
        (40000, 80, (40000, 80)),
        ("40000", "80", (40000, 80)),
        (65535, 0, (65535, 0)),
        (65536, 80, (None, 80)),
        (-1, 80, (None, 80)),
        (" 80", "8_0", (None, None)),
        ("٨٠", "80\n", (None, None)),
        (True, 80.0, (None, None)),
        ("", None, (None, None)),
    ],
)
def test_port_forms(src_port: object, dst_port: object, expected: tuple) -> None:
    normalized = preprocess_record(_with("transport", src_port=src_port, dst_port=dst_port))["normalized"]

    assert (normalized["src_port"], normalized["dst_port"]) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.1", "10.0.0.1"),
        ("2001:DB8::1", "2001:db8::1"),
        ("::FFFF:A00:1", "::ffff:10.0.0.1"),
        ("010.0.0.1", None),
        ("fe80::1%eth0", None),
        (167772161, None),
        (" 10.0.0.1", None),
        (None, None),
    ],
)
def test_ip_forms(value: object, expected: str | None) -> None:
    normalized = preprocess_record(_with("network", src_ip=value))["normalized"]

    assert normalized["src_ip"] == expected


def test_a_record_without_optional_fields_gets_null_and_empty_values() -> None:
    expected = {**empty_normalized(), "timestamp": TIMESTAMP, "timestamp_iso": "2025-09-21T08:00:00+00:00"}
    expected.update(protocol="TCP", src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000, dst_port=80)

    assert _normalized(_record(errors=...)) == expected


@pytest.mark.parametrize(
    "record",
    [_record(), _record(transport=None, network=None), _record(timestamp=...), "text", None],
    ids=["valid", "no-layers", "invalid", "text", "none"],
)
def test_every_normalized_key_is_present(record: object) -> None:
    assert preprocess_record(record)["normalized"].keys() == empty_normalized().keys()


def test_the_reason_holds_a_short_token_of_a_long_value() -> None:
    reason = preprocess_record(_with("transport", protocol="X" * 1_000_000))["reason"]

    assert len(reason) < 100


def _http(application: dict | None = None, **changes: object) -> dict:
    application = {"host": "example.com", "target": "/index.html", "headers": {"host": "example.com"}, **(application or {})}
    return _record(**{"app_protocol": "HTTP", "application": application, **changes})


def _dns(application: dict) -> dict:
    return _record(app_protocol="DNS", application=application)


def _normalized(record: dict) -> dict:
    return preprocess_record(record)["normalized"]


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("EXAMPLE.com.:80", "example.com"),
        ("[::1]:80", "::1"),
        ("::1", "::1"),
        ("[2001:DB8::1]", "2001:db8::1"),
        ("1.2.3.4:8080", "1.2.3.4"),
        (" Example.COM ", "example.com"),
        ("example.com:80:80", "example.com:80:80"),
        ("example.com:٨٠", "example.com:٨٠"),
        ("example.com..", "example.com."),
        ("[0:0:0:0:0:0:0:1]:80", "::1"),
        ("[::1", "[::1"),
        (".", None),
        (80, None),
    ],
)
def test_host_forms(host: object, expected: str | None) -> None:
    assert _normalized(_http({"host": host}))["host"] == expected


@pytest.mark.parametrize(
    ("target", "path", "query"),
    [
        ("/a/./b/../c", "/a/c", None),
        ("/a/b/c/./../../g", "/a/g", None),
        ("/a/b/..", "/a/", None),
        ("/a/.", "/a/", None),
        ("/../a", "/a", None),
        ("//x?y=1", "//x", "y=1"),
        ("/A/b?", "/A/b", ""),
        ("/a?b=c?d", "/a", "b=c?d"),
        ("*", None, None),
        ("http://example.com/", None, None),
        (None, None, None),
    ],
)
def test_path_and_query(target: object, path: str | None, query: str | None) -> None:
    normalized = _normalized(_http({"target": target}))

    assert (normalized["path"], normalized["query"]) == (path, query)


def test_the_decoded_target_wins_over_the_raw_target() -> None:
    decoded = ["text", {"field": "http.target", "value": None}, {"field": "http.target", "value": "/a/../b?x=1"}]

    normalized = _normalized(_http({"target": "/a/%2e%2e/b?x=1"}, decoded=decoded))

    assert (normalized["path"], normalized["query"]) == ("/b", "x=1")


def test_a_failed_decoded_target_falls_back_to_the_raw_target() -> None:
    decoded = [{"field": "http.target", "value": None, "status": "failed"}]

    assert _normalized(_http({"target": "/a/./b"}, decoded=decoded))["path"] == "/a/b"


def test_header_names_that_differ_in_case_merge_in_order() -> None:
    headers = {"Content-TYPE": "a", "content-type": ["b", " c "], " X ": " v ", "Bad": 5, 3: "x"}

    assert _normalized(_http({"headers": headers}))["headers"] == {"content-type": ["a", "b", "c"], "x": "v"}


def test_dns_names_are_lower_case_without_a_dot_and_without_duplicates() -> None:
    application = {
        "questions": [{"name": "WWW.Example.com."}, {"name": 5}, "text"],
        "answers": [{"name": "example.com."}, {"name": "www.example.com"}, {"name": ""}],
    }

    assert _normalized(_dns(application))["domains"] == ["www.example.com", "example.com"]


@pytest.mark.parametrize(
    ("record", "key", "empty"),
    [
        (_record(app_protocol="SMTP", application={"host": "x.com", "target": "/a", "headers": {"a": "b"}}), "host", None),
        (_record(app_protocol="SMTP", application={"host": "x.com", "target": "/a", "headers": {"a": "b"}}), "headers", {}),
        (_record(app_protocol="SMTP", application={"host": "x.com", "target": "/a", "headers": {"a": "b"}}), "path", None),
        (_http({"questions": [{"name": "x.com"}]}), "domains", []),
    ],
    ids=["smtp-host", "smtp-headers", "smtp-path", "http-domains"],
)
def test_application_fields_are_read_only_for_their_protocol(record: dict, key: str, empty: object) -> None:
    assert _normalized(record)[key] == empty


@pytest.mark.parametrize(
    ("flags", "expected"),
    [(["ack", "SYN", "bogus", 5], ["SYN", "ACK"]), (["FIN", "CWR", "ECE"], ["FIN", "ECE", "CWR"]), ("SYN", []), (None, [])],
)
def test_tcp_flags_come_in_a_fixed_order(flags: object, expected: list[str]) -> None:
    assert _normalized(_with("transport", flags=flags))["tcp_flags"] == expected


@pytest.mark.parametrize(
    ("changes", "key", "expected"),
    [
        ({"app_protocol": "http"}, "app_protocol", "HTTP"),
        ({"app_protocol": "FTP"}, "app_protocol", "UNKNOWN"),
        ({"app_protocol": None}, "app_protocol", "UNKNOWN"),
        ({"detection": {"method": "port+payload"}}, "detection_method", "port+payload"),
        ({"detection": {"method": "guess"}}, "detection_method", None),
        ({"detection": None}, "detection_method", None),
        ({"length": 54}, "length", 54),
        ({"length": 0}, "length", 0),
        ({"length": True}, "length", None),
        ({"payload_len": -1}, "payload_len", None),
        ({"payload_len": "5"}, "payload_len", None),
    ],
)
def test_other_fields(changes: dict, key: str, expected: object) -> None:
    assert _normalized(_record(**changes))[key] == expected


def test_records_in_different_case_and_format_give_the_same_normalized_view() -> None:
    plain = _http({"headers": {"content-type": "text/html"}, "target": "/a/b"})
    plain["network"] = {"src_ip": "2001:db8::1", "dst_ip": "10.0.0.2"}
    plain["transport"] = {"protocol": "TCP", "src_port": 40000, "dst_port": 80, "flags": ["SYN"]}
    other = _http(
        {"host": "EXAMPLE.com.:80", "headers": {"Content-TYPE": " text/html "}, "target": "/a/./c/../b"},
        app_protocol="Http", timestamp="2025-09-21T08:00:00",
    )
    other["network"] = {"src_ip": "2001:DB8::1", "dst_ip": "10.0.0.2"}
    other["transport"] = {"protocol": "tcp", "src_port": "40000", "dst_port": "80", "flags": ["syn"]}

    assert _normalized(other) == _normalized(plain)


def _case_variants(count: int) -> dict[str, str]:
    base = "abcdefghijklmnop"
    return {"".join(c.upper() if (i >> k) & 1 else c for k, c in enumerate(base)): "v" for i in range(count)}


@pytest.mark.parametrize(
    "record",
    [
        _dns({"questions": [{"name": f"a{i}.com"} for i in range(50_000)]}),
        _http({"headers": _case_variants(65_000)}),
    ],
    ids=["many-domains", "many-header-case-variants"],
)
def test_a_large_application_object_is_fast(record: dict) -> None:
    started = time.perf_counter()

    preprocess_record(record)

    assert time.perf_counter() - started < 1.0
