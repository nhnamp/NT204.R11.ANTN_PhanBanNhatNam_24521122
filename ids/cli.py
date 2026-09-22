"""Parse arguments, then wire a capture source to the pipeline and the writer."""

import argparse

from ids.config import Config


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
    """Print the parsed configuration. The capture loop replaces this body later."""
    origin = f"live:{config.interface}" if config.interface else f"pcap:{config.pcap}"
    print(f"source: {origin}")
    print(f"output: {config.output}")
    print(f"unknown: {config.unknown}")
    print(f"count: {config.count if config.count is not None else 'unlimited'}")
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
