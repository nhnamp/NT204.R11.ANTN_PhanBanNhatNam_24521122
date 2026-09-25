"""Shared pytest fixtures."""

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def basic_pcap() -> Path:
    """Point the capture tests at the committed PCAP fixture."""
    return FIXTURE_DIR / "basic.pcap"
