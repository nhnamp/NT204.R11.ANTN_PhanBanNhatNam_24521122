"""Shared pytest fixtures."""

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def basic_pcap() -> Path:
    """Point the capture tests at the committed PCAP fixture."""
    return FIXTURE_DIR / "basic.pcap"


@pytest.fixture(autouse=True)
def _work_in_a_temporary_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the files that a run writes by default, such as flows.jsonl, out of the repository."""
    monkeypatch.chdir(tmp_path)
