"""Parse arguments, then wire a capture source to the pipeline and the writer."""

import argparse
import logging
import math
import sys
import time

from ids.capture.base import PacketSource
from ids.capture.live import LiveSource
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
    parser.add_argument(
        "--payload",
        choices=("preview", "full"),
        default=Config.payload,
        help="store the payload in payload_hex (full) or not (preview) (default: %(default)s)",
    )
    parser.add_argument(
        "--payload-limit",
        metavar="N",
        type=_positive_int,
        default=Config.payload_limit,
        help="largest payload in bytes that is stored and decoded (default: %(default)s)",
    )
    parser.add_argument(
        "--tcp-timeout",
        metavar="SEC",
        type=_positive_float,
        default=Config.tcp_timeout,
        help="idle timeout of a TCP flow in seconds of packet time (default: %(default)s)",
    )
    parser.add_argument(
        "--udp-timeout",
        metavar="SEC",
        type=_positive_float,
        default=Config.udp_timeout,
        help="idle timeout of a UDP flow in seconds of packet time (default: %(default)s)",
    )
    parser.add_argument(
        "--max-flows",
        metavar="N",
        type=_positive_int,
        default=Config.max_flows,
        help="largest number of active flows (default: %(default)s)",
    )
    parser.add_argument(
        "--flows-output",
        metavar="FILE",
        default=Config.flows_output,
        help="write flow records to FILE (default: %(default)s)",
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
        payload=args.payload,
        payload_limit=args.payload_limit,
        tcp_timeout=args.tcp_timeout,
        udp_timeout=args.udp_timeout,
        max_flows=args.max_flows,
        flows_output=args.flows_output,
    )


def run(config: Config) -> int:
    # Scapy logs its own dissection warnings, such as a DNS pointer loop. The events already report these faults.
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    source = _build_source(config)

    pipeline = Pipeline(config, source.describe())
    started = time.monotonic()
    read = 0
    written = 0
    dropped = 0
    counts = dict.fromkeys(("ok", "partial", "unsupported", "malformed"), 0)
    try:
        with JsonLinesWriter(config.output) as writer:
            for packet in source:
                read += 1
                event = pipeline.process(packet)
                if event is not None:
                    writer.write(event)
                    written += 1
                    counts[event.status] += 1
                else:
                    dropped += 1
                if config.count is not None and read >= config.count:
                    break
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
    except PermissionError as exc:
        print(f"live capture needs root: rerun with sudo ({exc})", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        # Scapy reports an unknown interface name as a ValueError.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    elapsed = time.monotonic() - started

    print(
        f"packets read: {read}",
        f"events written: {written}",
        *[f"{status}: {count}" for status, count in counts.items()],
        f"dropped: {dropped}",
        f"elapsed: {elapsed:.3f}s",
        sep="\n",
        file=sys.stderr,
    )
    return 0


def _build_source(config: Config) -> PacketSource:
    if config.interface is not None:
        return LiveSource(config.interface, config.count)
    return PcapSource(config.pcap)


def _positive_int(text: str) -> int:
    """Reject a value below one. For --count this matters, because Scapy reads count=0 as unlimited."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _positive_float(text: str) -> float:
    """Reject nan and inf too: a comparison with nan is always false, so a flow would never expire."""
    try:
        value = float(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a finite number above 0")
    return value
