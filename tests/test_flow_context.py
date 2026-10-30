from pathlib import Path

from scapy.all import rdpcap

from ids.config import Config
from ids.enrich import Enricher
from ids.pipeline import Pipeline
from ids.stages.flow import FlowContext, FlowTracker

HANDSHAKE_PCAP = Path(__file__).parent / "fixtures" / "tcp_handshake.pcap"

CLIENT = ("10.0.0.1", 40000)
SERVER = ("10.0.0.2", 80)
START = 1758441600.0


def _view(source=CLIENT, destination=SERVER, protocol="TCP", flags=(), offset=0.0) -> dict:
    return {
        "protocol": protocol,
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "tcp_flags": list(flags),
        "timestamp": START + offset,
        "length": 60,
        "app_protocol": "UNKNOWN",
        "detection_method": None,
    }


def _state_after(tracker: FlowTracker, view: dict) -> str | None:
    tracker.update(view)
    return tracker.context(view).state


def test_context_follows_the_tcp_state_packet_by_packet() -> None:
    tracker = FlowTracker()

    assert _state_after(tracker, _view(flags=["SYN"])) == "HANDSHAKE"
    assert _state_after(tracker, _view(SERVER, CLIENT, flags=["SYN", "ACK"], offset=0.1)) == "HANDSHAKE"
    assert _state_after(tracker, _view(flags=["ACK"], offset=0.2)) == "ESTABLISHED"
    assert _state_after(tracker, _view(flags=["FIN", "ACK"], offset=0.3)) == "CLOSING"


def test_context_of_a_udp_flow_counts_both_directions_and_has_no_state() -> None:
    tracker = FlowTracker()
    query = _view(protocol="UDP", destination=("10.0.0.2", 53))
    flow_id, _, _ = tracker.update(query)
    tracker.update(_view(("10.0.0.2", 53), CLIENT, protocol="UDP", offset=0.1))

    assert tracker.context(query) == FlowContext(flow_id, "forward", None, 1, 1)


def test_context_of_an_unknown_flow_is_none() -> None:
    assert FlowTracker().context(_view()) is None


def test_enricher_gives_no_context_to_a_record_without_a_flow() -> None:
    enricher = Enricher(Config(None, None, "events.jsonl", "keep", None))
    output, _ = enricher.process({"source": "test"})

    assert enricher.flow_context(output) is None


def test_enricher_gives_the_state_of_each_record_of_a_handshake() -> None:
    config = Config(None, str(HANDSHAKE_PCAP), "events.jsonl", "keep", None)
    pipeline, enricher = Pipeline(config, "test"), Enricher(config)
    states = []
    for packet in rdpcap(str(HANDSHAKE_PCAP)):
        output, _ = enricher.process(pipeline.process(packet).to_dict())
        context = enricher.flow_context(output)
        assert context.flow_id == output["flow_id"]
        states.append((context.direction, context.state))

    assert states == [("forward", "HANDSHAKE"), ("backward", "HANDSHAKE"), ("forward", "ESTABLISHED")]
