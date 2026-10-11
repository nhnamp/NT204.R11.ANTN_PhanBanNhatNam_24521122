"""Tests for the enricher: the shape of its output and its stage guards."""

import pytest

from ids.config import Config
from ids.contract import ENRICHMENT_FIELDS, default_enrichment, empty_normalized
from ids.enrich import Enricher

RECORD = {"packet_id": 1, "timestamp": 1758441600.0, "status": "ok", "payload_hex": ""}


def _enricher() -> Enricher:
    return Enricher(Config(None, None, "events.jsonl", "keep", None))


def _keep(record: dict) -> dict:
    """Stand in for the preprocessor with a record that the tracker can read."""
    normalized = {
        **empty_normalized(),
        "timestamp": 1758441600.0,
        "protocol": "TCP",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 40000,
        "dst_port": 80,
    }
    return {"processing_action": "keep", "normalized": normalized}


def _raise(record: dict) -> dict:
    raise RuntimeError("boom")


def test_output_holds_every_enrichment_field_after_the_base_fields() -> None:
    output, exported = _enricher().process(RECORD)

    assert output is not None
    assert list(output) == list(RECORD) + list(ENRICHMENT_FIELDS)
    assert exported == []
    assert RECORD == {"packet_id": 1, "timestamp": 1758441600.0, "status": "ok", "payload_hex": ""}


def test_replay_discards_the_old_enrichment_and_keeps_only_the_input_errors() -> None:
    stale = {field: "stale" for field in ENRICHMENT_FIELDS}
    stale["processing_errors"] = [{"stage": "decoder", "type": "OldError", "message": "old"}]
    input_errors = [{"stage": "input", "type": "invalid_record", "message": "line 3"}]

    output, _ = _enricher().process({**RECORD, **stale}, input_errors)

    assert output["flow_id"] != "stale"
    assert output["processing_errors"] == input_errors


def test_replay_puts_the_enrichment_fields_in_the_fixed_order() -> None:
    scrambled = {"flow_id": "stale", **RECORD, "decode_status": "stale"}

    output, _ = _enricher().process(scrambled)

    assert list(output) == list(RECORD) + list(ENRICHMENT_FIELDS)


def test_records_do_not_share_their_lists() -> None:
    enricher = _enricher()
    first, _ = enricher.process(RECORD)
    second, _ = enricher.process(RECORD)

    first["decoded"].append("x")
    first["normalized"]["domains"].append("example.com")

    assert second["decoded"] == []
    assert second["normalized"]["domains"] == []


@pytest.mark.parametrize(("attribute", "stage"), [("_decode", "decoder"), ("_preprocess", "preprocessor")])
def test_a_failing_stage_keeps_the_record_whole_and_records_the_error(
    monkeypatch: pytest.MonkeyPatch, attribute: str, stage: str
) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, attribute, _raise)

    output, _ = enricher.process(RECORD)

    assert list(output) == list(RECORD) + list(ENRICHMENT_FIELDS)
    assert output["processing_errors"] == [{"stage": stage, "type": "RuntimeError", "message": "boom"}]


def test_a_failing_decoder_does_not_stop_the_later_stages(monkeypatch: pytest.MonkeyPatch) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_decode", _raise)
    monkeypatch.setattr(enricher, "_preprocess", lambda record: {"reason": "from preprocessor"})

    output, _ = enricher.process(RECORD)

    assert output["reason"] == "from preprocessor"


def test_a_failing_preprocessor_says_so_and_skips_the_tracker(monkeypatch: pytest.MonkeyPatch) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_preprocess", _raise)
    monkeypatch.setattr(enricher, "_track", _raise)

    output, _ = enricher.process(RECORD)

    assert output["reason"] == "preprocessor failed"
    assert output["processing_action"] == "skip_flow"
    assert [error["stage"] for error in output["processing_errors"]] == ["preprocessor"]


def test_a_failing_tracker_keeps_the_record_whole_and_records_the_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_preprocess", _keep)
    monkeypatch.setattr(enricher, "_track", _raise)

    output, exported = enricher.process(RECORD)

    assert list(output) == list(RECORD) + list(ENRICHMENT_FIELDS)
    assert exported == []
    assert [(error["stage"], error["type"]) for error in output["processing_errors"]] == [("flow", "RuntimeError")]


def test_a_stage_that_returns_an_unknown_field_is_a_stage_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_decode", lambda record: {"decode_status": "ok", "surprise": 1})

    output, _ = enricher.process(RECORD)

    assert "surprise" not in output
    assert output["decode_status"] != "ok"
    assert output["processing_errors"][0]["type"] == "KeyError"


def test_an_error_message_with_a_lone_surrogate_stays_writable(monkeypatch: pytest.MonkeyPatch) -> None:
    enricher = _enricher()

    def fail(record: dict) -> dict:
        raise RuntimeError("bad \ud800 value")

    monkeypatch.setattr(enricher, "_decode", fail)

    output, _ = enricher.process(RECORD)

    output["processing_errors"][0]["message"].encode("utf-8")


OWN_FIELDS = {
    "decoder": ("decode_status", "decoded"),
    "preprocessor": ("preprocess_status", "processing_action", "reason", "normalized"),
    "flow": ("flow_id", "direction"),
}


def _stage_that_writes_then_raises(stage: str):
    def run(record: dict) -> dict:
        for name in OWN_FIELDS[stage]:
            record[name] = "half"
        raise RuntimeError("boom")

    return run


def _stage_with_a_bad_result(stage: str):
    def run(record: dict) -> dict:
        return {**{name: "half" for name in OWN_FIELDS[stage]}, "processing_errors": None}

    return run


@pytest.mark.parametrize("make_stage", [_stage_that_writes_then_raises, _stage_with_a_bad_result])
@pytest.mark.parametrize("stage", ["decoder", "preprocessor", "flow"])
def test_a_stage_that_fails_halfway_leaves_none_of_its_fields_behind(
    monkeypatch: pytest.MonkeyPatch, make_stage, stage: str
) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_preprocess", _keep)
    broken = make_stage(stage)
    if stage == "decoder":
        monkeypatch.setattr(enricher, "_decode", broken)
    elif stage == "preprocessor":
        monkeypatch.setattr(enricher, "_preprocess", broken)
    else:
        monkeypatch.setattr(enricher, "_track", lambda record: (broken(record), []))

    output, _ = enricher.process(RECORD)

    defaults = default_enrichment()
    for name in OWN_FIELDS[stage]:
        expected = "preprocessor failed" if (stage, name) == ("preprocessor", "reason") else defaults[name]
        assert output[name] == expected
    assert [error["stage"] for error in output["processing_errors"]] == [stage]


def test_flows_that_left_the_table_are_kept_when_the_tracker_result_fails_to_merge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enricher = _enricher()
    monkeypatch.setattr(enricher, "_preprocess", _keep)
    left_the_table = [{"flow_id": "tcp-1"}]
    monkeypatch.setattr(enricher, "_track", lambda record: ({"surprise": 1}, left_the_table))

    output, exported = enricher.process(RECORD)

    assert exported == left_the_table
    assert output["processing_errors"][0]["stage"] == "flow"


@pytest.mark.parametrize(
    ("changes", "unknown", "dropped"),
    [
        ({"status": "unsupported"}, "drop", True),
        ({"timestamp": "yesterday"}, "drop", True),
        ({"status": "partial"}, "drop", False),
        ({"status": "unsupported"}, "keep", False),
        ({"timestamp": "yesterday"}, "keep", False),
    ],
    ids=["unsupported-dropped", "invalid-dropped", "partial-kept", "unsupported-kept-by-keep", "invalid-kept-by-keep"],
)
def test_the_unknown_policy_drops_unsupported_and_invalid_records(changes: dict, unknown: str, dropped: bool) -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", unknown, None))

    output, exported = enricher.process({**RECORD, **changes})

    assert (output is None) == dropped
    assert exported == []


@pytest.mark.parametrize("attribute", ["_decode", "_preprocess"])
def test_a_record_with_a_bug_entry_is_never_dropped(monkeypatch: pytest.MonkeyPatch, attribute: str) -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", "drop", None))
    monkeypatch.setattr(enricher, attribute, _raise)

    output, _ = enricher.process({**RECORD, "status": "unsupported"})

    assert [error["type"] for error in output["processing_errors"]] == ["RuntimeError"]


def test_an_input_error_of_a_known_type_does_not_keep_an_invalid_record() -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", "drop", None))
    typed = [{"stage": "input", "type": "invalid_record", "message": "line 3"}]
    bug = [{"stage": "input", "type": "TypeError", "message": "x"}]

    assert enricher.process({"source": "events:f:3"}, typed) == (None, [])
    assert enricher.process({"source": "events:f:3"}, bug)[0] is not None
