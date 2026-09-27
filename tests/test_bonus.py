"""Whole-pipeline checks for detection on non-standard ports (R10.3)."""

from pathlib import Path

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.pipeline import Pipeline

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _detected(name: str) -> list[tuple[str, str, str, str]]:
    """Run one fixture through the whole pipeline, and report how each packet was decided."""
    config = Config(interface=None, pcap=name, output="events.jsonl", unknown="keep", count=None)
    pipeline = Pipeline(config, f"pcap:{name}")
    events = [pipeline.process(packet) for packet in PcapSource(FIXTURE_DIR / name)]
    return [
        (
            event.app_protocol,
            event.detection.method,
            event.detection.confidence,
            event.detection.rule,
        )
        for event in events
        if event is not None
    ]


def test_http_on_8080() -> None:
    assert _detected("bonus_http_8080.pcap") == [
        ("HTTP", "port+payload", "high", "http_request"),
        ("HTTP", "port+payload", "high", "http_response"),
    ]


def test_http_on_3000() -> None:
    assert _detected("bonus_http_3000.pcap") == [("HTTP", "payload", "high", "http_request")]


def test_dns_on_1053() -> None:
    assert _detected("bonus_dns_1053.pcap") == [
        ("DNS", "payload", "high", "dns_udp"),
        ("DNS", "payload", "high", "dns_udp"),
    ]


def test_dns_over_tcp_on_9053() -> None:
    assert _detected("bonus_dns_tcp_9053.pcap") == [("DNS", "payload", "high", "dns_tcp")]


def test_smtp_on_2526() -> None:
    response = ("SMTP", "payload", "high", "smtp_response")
    command = ("SMTP", "payload", "high", "smtp_command")
    message_content = ("UNKNOWN", "none", "low", "")

    assert _detected("bonus_smtp_2526.pcap") == [
        response,
        command,
        response,
        command,
        response,
        command,
        response,
        command,
        response,
        message_content,
        response,
        command,
        response,
    ]


def test_the_traps_stay_unknown_until_the_payload_proves_otherwise() -> None:
    detected = _detected("bonus_traps.pcap")

    assert detected[:3] == [("UNKNOWN", "none", "low", "")] * 3
    assert detected[3] == ("HTTP", "payload", "high", "http_request")
