"""Tests for the event schema and its JSON-compatible conversion."""

import json

import pytest

from ids.events import Detection, Event, NetworkInfo, ParseError, TransportInfo


def _full_event() -> Event:
    """Build an event with every field set."""
    return Event(
        packet_id=1,
        timestamp=1758441600.5,
        timestamp_iso="2025-09-21T08:00:00.500000+00:00",
        source="pcap:basic.pcap",
        length=74,
        link_type="Ethernet",
        network=NetworkInfo(
            protocol="IPv4",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            version=4,
            header_len=20,
            dscp=0,
            total_len=60,
            identification=1234,
            flags=["DF"],
            frag_offset=0,
            ttl=64,
            proto_number=6,
            proto_name="TCP",
            checksum=4660,
            has_options=False,
        ),
        transport=TransportInfo(
            protocol="TCP",
            src_port=40000,
            dst_port=80,
            payload_len=20,
            checksum=22136,
            seq=1000,
            ack=0,
            data_offset=5,
            flags=["PSH", "ACK"],
            flags_raw=24,
            flags_str="PA",
            window=65535,
            urgent_ptr=0,
            options=[["MSS", 1460]],
            handshake=None,
        ),
        app_protocol="HTTP",
        detection=Detection(
            protocol="HTTP",
            method="payload",
            confidence="high",
            rule="http_request",
        ),
        application=None,
        payload_len=20,
        payload_preview="474554202f20485454502f312e310d0a",
        status="ok",
        errors=[ParseError(stage="network", type="fragment", message="non-first fragment")],
    )


def _minimal_event() -> Event:
    """Build an event with every optional layer absent."""
    return Event(
        packet_id=2,
        timestamp=1758441601.0,
        timestamp_iso="2025-09-21T08:00:01+00:00",
        source="live:en0",
        length=42,
        link_type="Ethernet",
        network=None,
        transport=None,
        app_protocol="UNKNOWN",
        detection=None,
        application=None,
        payload_len=0,
        payload_preview="",
        status="unsupported",
        errors=[],
    )


@pytest.mark.parametrize("event", [_full_event(), _minimal_event()])
def test_to_dict_round_trips_through_json(event: Event) -> None:
    """A serialized event must survive json.dumps and json.loads unchanged."""
    data = event.to_dict()

    assert json.loads(json.dumps(data, ensure_ascii=False)) == data


def test_to_dict_maps_nested_dataclasses_to_dicts() -> None:
    """Nested types and error entries must become plain dicts and lists."""
    data = _full_event().to_dict()

    assert data["network"]["src_ip"] == "10.0.0.1"
    assert data["transport"]["options"] == [["MSS", 1460]]
    assert data["detection"]["method"] == "payload"
    assert data["errors"] == [
        {"stage": "network", "type": "fragment", "message": "non-first fragment"}
    ]


def test_to_dict_rejects_a_non_json_value() -> None:
    """A bytes value must fail loudly instead of reaching json.dumps."""
    event = _full_event()
    event.payload_preview = b"\xde\xad"

    with pytest.raises(TypeError):
        event.to_dict()
