"""Tests for the live capture source."""

import pytest
from scapy.all import Ether, IP, UDP
from scapy.error import Scapy_Exception

from ids.capture.live import LiveSource


def test_live_source_yields_the_collected_packets(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_sniff(*, prn, **kwargs: object) -> None:
        for _ in range(3):
            prn(Ether() / IP() / UDP())

    monkeypatch.setattr("ids.capture.live.sniff", fake_sniff)

    packets = list(LiveSource("lo0", count=3))

    assert len(packets) == 3


def test_describe_names_the_interface() -> None:
    assert LiveSource("en0").describe() == "live:en0"


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Permission denied: could not open /dev/bpf0.", PermissionError),
        ("Some other capture failure", OSError),
    ],
)
def test_a_scapy_failure_reaches_the_caller(
    monkeypatch: pytest.MonkeyPatch, message: str, expected: type[Exception]
) -> None:
    def fake_sniff(**kwargs: object) -> None:
        raise Scapy_Exception(message)

    monkeypatch.setattr("ids.capture.live.sniff", fake_sniff)

    with pytest.raises(expected) as caught:
        list(LiveSource("en0"))
    assert type(caught.value) is expected
