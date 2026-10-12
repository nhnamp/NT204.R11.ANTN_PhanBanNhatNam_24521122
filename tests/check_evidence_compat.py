"""Check that the enrichment stages leave the base fields of the committed evidence unchanged.

Run it from anywhere: `python tests/check_evidence_compat.py`.
For each pair of an input and a committed output, it reruns `python main.py` into a temporary file.
It removes the enrichment fields and `payload_hex` from both sides, then compares the rest.
The key order counts, because a moved key breaks the `git diff` of a retest.
It exits 1 at the first difference, and it names the file and the line.
"""

import json
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ids.contract import ENRICHMENT_FIELDS, PAYLOAD_FIELD  # noqa: E402

TEST_DIR = ROOT / "TEST"
REMOVED_FIELDS = (*ENRICHMENT_FIELDS, PAYLOAD_FIELD)


class Difference(Exception):
    """A rerun does not match the committed file."""


def _pairs(folder: Path) -> Iterator[tuple[Path, str, Path]]:
    """Yield (input, unknown policy, committed output) for the files that the folder holds.

    Every input needs one output in each output directory that the folder has. A single input needs `output.jsonl`.
    """
    if (folder / "input").is_dir():
        directories = [(policy, name) for policy, name in (("keep", "output"), ("drop", "output_drop")) if (folder / name).is_dir()]
        for source in sorted(path for path in (folder / "input").iterdir() if not path.name.startswith(".")):
            for policy, directory in directories:
                yield source, policy, _required(folder / directory / f"{source.stem}.jsonl")
    else:
        for source in sorted(folder.glob("input.*")):
            yield source, "keep", _required(folder / "output.jsonl")
            if (folder / "output_drop.jsonl").exists():
                yield source, "drop", folder / "output_drop.jsonl"


def _required(path: Path) -> Path:
    if not path.exists():
        raise Difference(f"{path.relative_to(ROOT)} is missing")
    return path


def _committed_outputs(folder: Path) -> set[Path]:
    """List the committed output files that the convention can pair with an input."""
    found = {path for path in (folder / "output.jsonl", folder / "output_drop.jsonl") if path.exists()}
    for directory in ("output", "output_drop"):
        found.update((folder / directory).glob("*.jsonl"))
    return found


def _run(source: Path, policy: str, output: Path, flows: Path) -> None:
    option = "--events" if source.suffix == ".jsonl" else "--pcap"
    command = [
        sys.executable, "main.py", option, str(source.relative_to(ROOT)),
        "--output", str(output), "--flows-output", str(flows), "--unknown", policy,
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise Difference(f"{source.relative_to(ROOT)} --unknown {policy}: exit code {result.returncode}\n{result.stderr}")


def _base_records(path: Path) -> list[str]:
    """Return one text per line: the record without the removed fields, with the key order kept."""
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except ValueError as exc:
            raise Difference(f"{path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}:{number}: not JSON ({exc})") from exc
        records.append(json.dumps({key: value for key, value in record.items() if key not in REMOVED_FIELDS}, ensure_ascii=False))
    return records


def _compare(committed: Path, fresh: Path) -> None:
    name = committed.relative_to(ROOT)
    old, new = _base_records(committed), _base_records(fresh)
    if len(old) != len(new):
        raise Difference(f"{name}: {len(old)} lines are committed and the rerun writes {len(new)}")
    for number, (before, after) in enumerate(zip(old, new), 1):
        if before != after:
            old_record, new_record = json.loads(before), json.loads(after)
            if list(old_record) != list(new_record):
                raise Difference(f"{name}:{number}: the keys differ: {list(old_record)} and {list(new_record)}")
            key = next(key for key in old_record if old_record[key] != new_record[key])
            raise Difference(f"{name}:{number}: the value of `{key}` differs")


def _check_folder(folder: Path, output: Path, flows: Path) -> int:
    covered: set[Path] = set()
    for source, policy, committed in _pairs(folder):
        _run(source, policy, output, flows)
        _compare(committed, output)
        covered.add(committed)
    # An output without an input, or an input without an output, would pass unseen.
    unpaired = _committed_outputs(folder) - covered
    if unpaired or (not covered and any(folder.glob("input*"))):
        names = ", ".join(str(path.relative_to(ROOT)) for path in sorted(unpaired)) or "no committed output"
        raise Difference(f"the files do not pair up: {names}")
    return len(covered)


def main() -> int:
    started = time.perf_counter()
    checked = 0
    with tempfile.TemporaryDirectory() as temporary:
        output, flows = Path(temporary) / "output.jsonl", Path(temporary) / "flows.jsonl"
        for folder in sorted(path for path in TEST_DIR.iterdir() if path.is_dir()):
            try:
                checked += _check_folder(folder, output, flows)
            except Difference as exc:
                print(f"DIFFERENCE in {folder.name}: {exc}")
                return 1
    print(f"checked {checked} outputs: the base fields are unchanged ({time.perf_counter() - started:.1f} s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
