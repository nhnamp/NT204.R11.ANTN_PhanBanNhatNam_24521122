"""Fuzz tests: mutated records and packets must never make a stage raise through the Enricher (R8.3, R8.4)."""

import copy
import json
import random
import time
from typing import Any

import pytest
from scapy.all import Raw

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.contract import ENRICHMENT_FIELDS, TYPED_ERRORS
from ids.enrich import Enricher
from ids.pipeline import Pipeline
from tests.test_fuzz import FIXTURE_DIR, SEED as PACKET_SEED, _fixture_packets, _mutate

SEED = 20261012
MUTATIONS = 200
BUDGET_SECONDS = 1.0
# Only values that the events reader can deliver. It rejects NaN, infinity, and a lone surrogate before any stage.
OTHER_VALUES = (None, True, 0, -1, 7, 2.5, "text", "", [], {}, [1, "a"], {"a": 1})
LARGE_NUMBERS = (2**63, 10**30, 1e308)


def _config(unknown: str) -> Config:
    return Config(interface=None, pcap="fuzz", output="events.jsonl", unknown=unknown, count=None)  # type: ignore[arg-type]


def _check(result: tuple[dict | None, list[dict]]) -> None:
    """Apply the four asserts of R8.3 to the result of `Enricher.process`."""
    output, exported = result
    assert output is None or isinstance(output, dict)
    if output is not None:
        assert set(ENRICHMENT_FIELDS) <= output.keys()
        # A class name in processing_errors means that a stage raised an exception that the guard hid.
        assert {error["type"] for error in output["processing_errors"]} <= set(TYPED_ERRORS)
    for record in ([output] if output is not None else []) + exported:
        json.dumps(record, ensure_ascii=False, allow_nan=False).encode("utf-8")


def _fixture_records() -> list[dict]:
    """Build the records of every fixture PCAP, as the pipeline writes them. all.pcap only repeats them."""
    records: list[dict] = []
    for path in sorted(FIXTURE_DIR.glob("*.pcap")):
        if path.name != "all.pcap":
            pipeline = Pipeline(_config("keep"), f"pcap:{path.name}")
            records.extend(pipeline.process(packet).to_dict() for packet in PcapSource(path))
    return records


def _slots(node: dict | list, found: list[tuple[Any, Any]]) -> None:
    for key, child in list(node.items() if isinstance(node, dict) else enumerate(node)):
        found.append((node, key))
        if isinstance(child, (dict, list)):
            _slots(child, found)


def _mutate_record(record: dict, rng: random.Random) -> dict:
    """Change one value somewhere in the record."""
    mutated = copy.deepcopy(record)
    slots: list[tuple[Any, Any]] = []
    _slots(mutated, slots)
    container, key = rng.choice(slots)
    value = container[key]
    kind = rng.choice(("replace", "delete", "cut", "repeat", "large"))
    if kind == "delete":
        del container[key]
    elif kind == "cut" and isinstance(value, str):
        container[key] = value[: rng.randrange(len(value) + 1)]
    elif kind == "repeat" and isinstance(value, list):
        container[key] = value * rng.choice((2, 50))
    elif kind == "large":
        container[key] = rng.choice(LARGE_NUMBERS)
    else:
        container[key] = rng.choice([other for other in OTHER_VALUES if type(other) is not type(value)])
    return mutated


def test_mutated_records_never_escape_the_enricher() -> None:
    rng = random.Random(SEED)
    enrichers = [Enricher(_config("keep")), Enricher(_config("drop"))]
    records = _fixture_records()
    processed = 0
    for record in records:
        for _ in range(MUTATIONS):
            mutated = _mutate_record(record, rng)
            for enricher in enrichers:
                _check(enricher.process(copy.deepcopy(mutated)))
            processed += 1
    for enricher in enrichers:
        _check((None, enricher.flush()))

    assert processed == len(records) * MUTATIONS


def test_mutated_packets_never_escape_the_pipeline_and_the_enricher() -> None:
    # The seed of the packet fuzz test, so this test runs the same mutated packets through the whole chain.
    rng = random.Random(PACKET_SEED)
    pipeline = Pipeline(_config("keep"), "fuzz")
    enrichers = [Enricher(_config("keep")), Enricher(_config("drop"))]
    packets = _fixture_packets()
    for original in packets:
        data = bytes(original)
        for _ in range(MUTATIONS):
            mutated = _mutate(data, rng)
            try:
                packet = type(original)(mutated)
            except Exception:
                # PcapReader falls back to Raw when Scapy cannot dissect a frame, so the fuzz input does too.
                packet = Raw(mutated)
            started = time.perf_counter()
            event = pipeline.process(packet)
            results = [enricher.process(event.to_dict()) for enricher in enrichers]
            assert time.perf_counter() - started < BUDGET_SECONDS, mutated.hex()
            for result in results:
                _check(result)
    for enricher in enrichers:
        _check((None, enricher.flush()))


def test_the_check_fails_when_a_stage_raises_an_unexpected_exception() -> None:
    def broken(record: dict) -> dict:
        raise RuntimeError("stage double")

    enricher = Enricher(_config("keep"))
    enricher._decode = broken  # type: ignore[assignment]
    record = _fixture_records()[0]

    with pytest.raises(AssertionError, match="RuntimeError"):
        _check(enricher.process(record))
