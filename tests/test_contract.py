"""Tests for the event field contract."""

from dataclasses import fields

from ids.contract import (
    BASE_FIELDS,
    ENRICHMENT_FIELDS,
    PAYLOAD_FIELD,
    default_enrichment,
    empty_normalized,
)
from ids.events import Event


def test_enrichment_fields_are_unique_and_do_not_reuse_a_base_name() -> None:
    names = BASE_FIELDS + (PAYLOAD_FIELD,) + ENRICHMENT_FIELDS
    assert len(set(names)) == len(names)


def test_event_fields_are_the_base_fields_and_the_payload_field() -> None:
    event_fields = tuple(item.name for item in fields(Event))
    assert event_fields == BASE_FIELDS + (PAYLOAD_FIELD,)


def test_defaults_cover_every_enrichment_field_in_order() -> None:
    assert tuple(default_enrichment()) == ENRICHMENT_FIELDS


def test_defaults_are_new_objects_on_every_call() -> None:
    first, second = default_enrichment(), default_enrichment()

    first["decoded"].append("x")
    first["normalized"]["domains"].append("example.com")

    assert second["decoded"] == []
    assert empty_normalized()["domains"] == []
