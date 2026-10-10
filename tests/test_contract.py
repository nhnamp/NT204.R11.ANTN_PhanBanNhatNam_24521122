"""Tests for the event field contract."""

from dataclasses import fields

from ids.contract import BASE_FIELDS, ENRICHMENT_FIELDS, PAYLOAD_FIELD
from ids.events import Event


def test_enrichment_fields_are_unique_and_do_not_reuse_a_base_name() -> None:
    names = BASE_FIELDS + (PAYLOAD_FIELD,) + ENRICHMENT_FIELDS
    assert len(set(names)) == len(names)


def test_event_fields_are_the_base_fields_and_the_payload_field() -> None:
    event_fields = tuple(item.name for item in fields(Event))
    assert event_fields == BASE_FIELDS + (PAYLOAD_FIELD,)
