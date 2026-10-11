"""Tests that run the decoder fixtures through the pipeline and the enricher, as the CLI does."""

from pathlib import Path

import pytest

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.enrich import Enricher
from ids.pipeline import Pipeline

FIXTURE_DIR = Path(__file__).parent / "fixtures"
REPLACED = "�"


def _enrich(name: str) -> list[dict]:
    config = Config(interface=None, pcap=name, output="out.jsonl", unknown="keep", count=None)
    pipeline, enricher = Pipeline(config, f"pcap:{name}"), Enricher(config)
    records = [pipeline.process(packet).to_dict() for packet in PcapSource(FIXTURE_DIR / name)]
    return [enricher.process(record)[0] for record in records]


def _items(record: dict) -> dict[str, tuple]:
    return {item["field"]: (item["value"], item["status"]) for item in record["decoded"]}


@pytest.mark.parametrize(
    ("name", "index", "status", "items"),
    [
        ("http_percent.pcap", 0, "ok", {"http.target": ("/search?q=' OR 1=1", "ok")}),
        ("http_percent.pcap", 1, "ok", {"http.target": ("/a+b?c d=e+f", "ok")}),
        ("http_percent.pcap", 2, "ok", {"http.body": ("user=' OR 1=1&note=a+b", "ok")}),
        ("http_percent.pcap", 3, "partial", {"http.target": ("/p?q=%zz", "partial")}),
        ("http_entity.pcap", 0, "ok", {"http.body": ("<script>alert(1)</script>", "ok")}),
        ("http_entity.pcap", 1, "not_applicable", {}),
        ("http_entity.pcap", 2, "ok", {"http.body": ("<b>", "ok")}),
        ("invalid_utf8.pcap", 1, "partial", {"payload": (f"plain text {REPLACED}{REPLACED}{REPLACED} more plain text", "partial")}),
        ("invalid_utf8.pcap", 2, "partial", {"payload": (None, "partial")}),
    ],
    ids=[
        "T01-percent-target", "T01-plus-in-query", "T01-form-body", "T01-bad-escape",
        "T02-entity-in-html", "T02-no-semicolon-kept", "T02-no-content-type",
        "T04-few-bad-bytes", "T04-random-binary",
    ],
)
def test_fixture_packet_decodes_as_the_case_expects(name: str, index: int, status: str, items: dict) -> None:
    record = _enrich(name)[index]

    assert record["decode_status"] == status
    assert _items(record) == items
    assert record["processing_errors"] == []


def test_the_raw_target_stays_intact_beside_the_decoded_one() -> None:
    record = _enrich("http_percent.pcap")[0]

    assert record["application"]["target"] == "/search?q=%27%20OR%201%3D1"


def test_bad_bytes_in_an_http_body_are_reported_by_the_payload_item() -> None:
    record = _enrich("invalid_utf8.pcap")[0]

    assert record["app_protocol"] == "HTTP"
    assert record["decode_status"] == "partial"
    assert [item["reason"] for item in record["decoded"]] == ["invalid UTF-8: 3 invalid sequences replaced"]
