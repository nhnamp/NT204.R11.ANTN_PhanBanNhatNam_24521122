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
        "valid", "no-status", "lower-case-protocol", "port-zero", "epoch-zero", "last-second", "bool-offset",
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
