"""Parse arguments, then wire a capture source to the pipeline and the writer."""

import argparse
import sys
import time

from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.output import JsonLinesWriter
from ids.pipeline import Pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Capture packets and write one event per packet as JSON Lines.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", metavar="IFACE", help="capture live traffic from IFACE")
    source.add_argument("--pcap", metavar="FILE", help="read packets from the PCAP file FILE")
    parser.add_argument(
        "--output",
        metavar="FILE",
        default="events.jsonl",
        help="write events to FILE (default: %(default)s)",
    )
    parser.add_argument(
        "--unknown",
        choices=("keep", "drop"),
        default="keep",
        help="keep or drop unsupported packets (default: %(default)s)",
    )
    parser.add_argument(
        "--count",
        metavar="N",
        type=_positive_int,
        default=None,
        help="stop after N packets",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> Config:
    args = build_parser().parse_args(argv)
    return Config(
        interface=args.interface,
        pcap=args.pcap,
        output=args.output,
        unknown=args.unknown,
        count=args.count,
    )


def run(config: Config) -> int:
    if config.interface is not None:
        print("live capture is not implemented yet", file=sys.stderr)
        return 1
    source = PcapSource(config.pcap)

    pipeline = Pipeline(config, source.describe())
    started = time.monotonic()
    read = 0
    written = 0
    unsupported = 0
    malformed = 0
    try:
        with JsonLinesWriter(config.output) as writer:
            for packet in source:
                read += 1
                event = pipeline.process(packet)
                if event is not None:
                    writer.write(event)
                    written += 1
                    if event.status == "unsupported":
                        unsupported += 1
                    elif event.status == "malformed":
                        malformed += 1
                if config.count is not None and read >= config.count:
                    break
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    print(
        f"packets read: {read}",
        f"events written: {written}",
        f"unsupported: {unsupported}",
        f"malformed: {malformed}",
        f"elapsed: {elapsed:.3f}s",
        sep="\n",
        file=sys.stderr,
    )
    return 0


def _positive_int(text: str) -> int:
    """Reject a count below one, because Scapy reads count=0 as unlimited."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("count must be an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("count must be at least 1")
    return value
