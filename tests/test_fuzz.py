"""Fuzz test: mutated fixture packets must never escape the pipeline (R9.3)."""

import random
from pathlib import Path

from scapy.all import Raw
from scapy.packet import Packet

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.events import Event
from ids.pipeline import Pipeline

FIXTURE_DIR = Path(__file__).parent / "fixtures"
SEED = 20261005
MUTATIONS = 200
# The outer guard of Pipeline.process turns any exception into an event, so a test on the
# event alone cannot fail. A stage guard names the exception class, so any other type is a parser bug.
TYPED_ERRORS = {"truncated", "malformed", "limit", "fragment"}


def _fixture_packets() -> list[Packet]:
    """Load the fixture packets once, in a stable order. all.pcap only repeats them."""
    packets: list[Packet] = []
    for path in sorted(FIXTURE_DIR.glob("*.pcap")):
        if path.name != "all.pcap":
            packets.extend(PcapSource(path))
    return packets


def _mutate(data: bytes, rng: random.Random) -> bytes:
    """Flip, truncate, or insert bytes, so a mutation can break any header."""
    if not data:
        return bytes(rng.randrange(256) for _ in range(4))
    kind = rng.choice(("flip", "truncate", "insert"))
    if kind == "flip":
        index = rng.randrange(len(data))
        return data[:index] + bytes([data[index] ^ (1 << rng.randrange(8))]) + data[index + 1 :]
    if kind == "truncate":
        return data[: rng.randrange(len(data))]
    index = rng.randrange(len(data))
    return data[:index] + bytes([rng.randrange(256)]) + data[index:]


def test_mutated_fixture_packets_never_escape_the_pipeline() -> None:
    rng = random.Random(SEED)
    config = Config(interface=None, pcap="fuzz", output="events.jsonl", unknown="keep", count=None)
    pipeline = Pipeline(config, "fuzz")
    packets = _fixture_packets()
    processed = 0
    for original in packets:
        data = bytes(original)
        for _ in range(MUTATIONS):
            mutated = _mutate(data, rng)
            try:
                packet = type(original)(mutated)
            except Exception:
                # PcapReader falls back to Raw when Scapy cannot dissect a frame, so the fuzz input does too.
                packet = Raw(mutated)
            event = pipeline.process(packet)
            processed += 1
            assert event is None or isinstance(event, Event)
            if event is not None:
                assert all(error.type in TYPED_ERRORS for error in event.errors), (mutated.hex(), event.errors)

    assert processed == len(packets) * MUTATIONS
