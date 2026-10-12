"""Tests that run the bad record corpus through the CLI (GEN-1: no input stops the run)."""

import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run
from ids.contract import TYPED_ERRORS
from tests.fixtures.build_pcaps import CORPUS_DIR, large_corpus_files

CASES = sorted([*(path.stem for path in CORPUS_DIR.glob("*.jsonl")), *large_corpus_files()])


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not strict JSON")


def _read_strict(path: Path) -> list[dict]:
    return [json.loads(line, parse_constant=_reject_constant) for line in path.read_text(encoding="utf-8").splitlines()]


def _case_file(name: str, tmp_path: Path) -> Path:
    committed = CORPUS_DIR / f"{name}.jsonl"
    if committed.exists():
        return committed
    path = tmp_path / f"{name}.jsonl"
    path.write_bytes(b"\n".join(large_corpus_files()[name]) + b"\n")
    return path


@pytest.mark.parametrize("unknown", ["keep", "drop"])
@pytest.mark.parametrize("name", CASES)
def test_a_bad_record_does_not_stop_the_run_and_no_stage_raises(name: str, unknown: str, tmp_path: Path) -> None:
    output, flows = tmp_path / "out.jsonl", tmp_path / "flows.jsonl"
    arguments = ["--events", str(_case_file(name, tmp_path)), "--output", str(output), "--flows-output", str(flows), "--unknown", unknown]

    assert run(parse_args(arguments)) == 0

    events = _read_strict(output)
    _read_strict(flows)
    # The last line of every case is a good record. It gets a flow only if the run went on after the bad ones.
    assert events[-1]["flow_id"] is not None
    # A class name in processing_errors means that a stage raised an exception that the guard hid.
    errors = [error["type"] for event in events for error in event["processing_errors"]]
    assert set(errors) <= set(TYPED_ERRORS)
