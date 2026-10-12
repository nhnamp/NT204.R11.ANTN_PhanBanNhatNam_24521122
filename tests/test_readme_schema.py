import json
import re
from pathlib import Path

import pytest

from ids.contract import BASE_FIELDS, ENRICHMENT_FIELDS, PAYLOAD_FIELD, empty_normalized

ROOT = Path(__file__).resolve().parents[1]
FLOW_EVIDENCE = ROOT / "TEST" / "A2-T13_flow_statistics" / "flows.jsonl"


def _documented_names(heading: str) -> set[str]:
    """Return the backticked names in the first column of the table under the heading."""
    names: set[str] = set()
    inside = False
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines():
        if line == heading:
            inside = True
        elif inside and line.startswith("#"):
            break
        elif inside and line.startswith("|"):
            names.update(re.findall(r"`([^`]+)`", line.split("|")[1]))
    return names


@pytest.mark.parametrize(
    ("heading", "expected"),
    [
        ("### Event", {*BASE_FIELDS, PAYLOAD_FIELD}),
        ("### Enrichment fields", set(ENRICHMENT_FIELDS)),
        ("### `normalized`", set(empty_normalized())),
        ("### Flow record", set(json.loads(FLOW_EVIDENCE.read_text().splitlines()[0]))),
    ],
)
def test_the_readme_table_names_exactly_the_keys_of_the_contract(heading: str, expected: set[str]) -> None:
    assert _documented_names(heading) == expected
