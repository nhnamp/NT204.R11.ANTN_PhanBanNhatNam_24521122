"""Parse arguments, then wire a capture source to the pipeline and the writer."""

import argparse
import logging
import math
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, get_args

from ids.capture.base import PacketSource
from ids.capture.events import EventFileSource
from ids.capture.live import LiveSource
from ids.capture.pcap import PcapSource
from ids.config import Config
from ids.contract import PREPROCESS_STATUSES
from ids.enrich import Enricher, fallback_record, input_failure
from ids.events import Status
from ids.output import JsonLinesWriter
from ids.pipeline import Pipeline

STATUSES = get_args(Status)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Capture packets and write one event per packet as JSON Lines.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", metavar="IFACE", help="capture live traffic from IFACE")
    source.add_argument("--pcap", metavar="FILE", help="read packets from the PCAP file FILE")
    source.add_argument("--events", metavar="FILE", help="read JSON Lines records from FILE")
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
    parser = build_parser()
    args = parser.parse_args(argv)
    # Two writers on one file truncate it together, and an output on the input file empties the input.
    if _same_file(args.output, args.flows_output):
        parser.error("--output and --flows-output name the same file")
    for name, path in (("--output", args.output), ("--flows-output", args.flows_output)):
        for source in (args.pcap, args.events):
            if source is not None and _same_file(path, source):
                parser.error(f"{name} names the input file")
    return Config(
        interface=args.interface,
        pcap=args.pcap,
        output=args.output,
        unknown=args.unknown,
        count=args.count,
        events=args.events,
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
    enricher = Enricher(config)
    started = time.monotonic()
    read = 0
    written = 0
    dropped = 0
    flows_written = 0
    counts = dict.fromkeys((*STATUSES, "other"), 0)
    preprocess_counts = dict.fromkeys((*PREPROCESS_STATUSES, "other"), 0)
    try:
        with JsonLinesWriter(config.output) as writer, JsonLinesWriter(config.flows_output) as flow_writer:
            try:
                for item in source:
                    read += 1
                    record, input_errors = _to_record(item, pipeline, source.describe())
                    output, exported = (
                        enricher.process(record, input_errors) if record is not None else (None, [])
                    )
                    flows_written += _write_flows(flow_writer, exported)
                    result = _write_record(writer, output) if output is not None else None
                    if result is None:
                        dropped += 1
                    else:
                        written += 1
                        counts[_bucket(result.get("status"), STATUSES)] += 1
                        preprocess_counts[_bucket(result.get("preprocess_status"), PREPROCESS_STATUSES)] += 1
                    if config.count is not None and read >= config.count:
                        break
            finally:
                flows_written += _export_remaining(enricher, flow_writer)
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
        *[f"preprocess {status}: {count}" for status, count in preprocess_counts.items()],
        f"dropped: {dropped}",
        f"flows written: {flows_written}",
        f"elapsed: {elapsed:.3f}s",
        sep="\n",
        file=sys.stderr,
    )
    return 0


def _to_record(item: Any, pipeline: Pipeline, source_name: str) -> tuple[dict | None, list[dict]]:
    """Turn what a source yields into a record. This is the one call site of Pipeline.process."""
    if isinstance(item, tuple):
        return item
    event = pipeline.process(item)
    if event is None:
        return None, []
    try:
        return event.to_dict(), []
    except (TypeError, ValueError, RecursionError) as exc:
        return input_failure(source_name, exc)


def _write_record(writer: JsonLinesWriter, record: dict) -> dict | None:
    """Write the record. When it cannot be written, write a smaller one, and return what was written."""
    try:
        writer.write(record)
        return record
    except ValueError as exc:
        for keep_base in (True, False):
            fallback = fallback_record(record, exc, keep_base=keep_base)
            try:
                writer.write(fallback)
                return fallback
            except ValueError:
                continue
    return None


def _write_flows(writer: JsonLinesWriter, flows: list[dict]) -> int:
    written = 0
    for flow in flows:
        try:
            writer.write(flow)
        except ValueError as exc:
            print(f"warning: a flow record could not be written ({exc})", file=sys.stderr)
        else:
            written += 1
    return written


def _export_remaining(enricher: Enricher, writer: JsonLinesWriter) -> int:
    try:
        return _write_flows(writer, enricher.flush())
    # The run can already end on another exception, and the export must not hide it.
    except Exception as exc:
        print(f"warning: the remaining flows were not exported ({exc})", file=sys.stderr)
        return 0


def _bucket(value: object, known: tuple[str, ...]) -> str:
    # `in` on a tuple compares with ==, so a list or a dict from a bad record gives "other", not an error.
    return value if value in known else "other"


def _same_file(first: str, second: str) -> bool:
    return Path(first).resolve() == Path(second).resolve()


def _build_source(config: Config) -> PacketSource | EventFileSource:
    if config.events is not None:
        return EventFileSource(config.events)
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
