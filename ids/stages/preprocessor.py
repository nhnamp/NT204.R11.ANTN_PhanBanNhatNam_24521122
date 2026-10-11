"""Validate one record and build its normalized view."""

import ipaddress
import re
from datetime import datetime, timezone

from ids.contract import empty_normalized

MAX_TIMESTAMP = 4_102_444_800
TRACKED_PROTOCOLS = ("TCP", "UDP")
MAX_PORT = 65_535
TOKEN_LIMIT = 32
PORT_TEXT = re.compile(r"[0-9]{1,5}")


def preprocess_record(record: dict) -> dict:
    normalized = empty_normalized()
    if not isinstance(record, dict):
        return _result("invalid", "record is not an object", normalized)

    seconds = _timestamp(record)
    if seconds is not None:
        normalized["timestamp"] = seconds
        normalized["timestamp_iso"] = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    problems = _fill_flow_fields(record, normalized)

    if seconds is None:
        return _result("invalid", "timestamp is missing or unusable", normalized)
    if problems:
        return _result("partial", "; ".join(problems), normalized)
    status = record.get("status")
    if status not in (None, "ok"):
        return _result("partial", f"packet status is {_token(status)}", normalized, action="keep")
    return _result("valid", None, normalized, action="keep")


def _result(status: str, reason: str | None, normalized: dict, action: str = "skip_flow") -> dict:
    return {
        "preprocess_status": status,
        "processing_action": action,
        "reason": reason,
        "normalized": normalized,
    }


def _token(value: object) -> str:
    """Return a short text of a value, because a value from an events file can be 1 MB."""
    return value[:TOKEN_LIMIT] if isinstance(value, str) else "not text"


def _timestamp(record: dict) -> float | None:
    value = record.get("timestamp")
    if value is None:
        value = record.get("timestamp_iso")
    if isinstance(value, bool):
        return None
    try:
        if isinstance(value, (int, float)):
            seconds = float(value)
        elif isinstance(value, str):
            seconds = _iso_seconds(value)
        else:
            return None
    except (ValueError, OverflowError, OSError):
        return None
    return seconds if 0 <= seconds <= MAX_TIMESTAMP else None


def _iso_seconds(text: str) -> float:
    moment = datetime.fromisoformat(text)
    # fromisoformat alone reads a naive time in the local zone, so the result would depend on the machine.
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _fill_flow_fields(record: dict, normalized: dict) -> list[str]:
    """Fill the protocol, the addresses, and the ports. Return the causes that block the flow."""
    network = record.get("network") if isinstance(record.get("network"), dict) else None
    transport = record.get("transport") if isinstance(record.get("transport"), dict) else None
    problems = []
    if network is None:
        problems.append("no network layer")
    if _is_non_first_fragment(record, network):
        problems.append("non-first fragment")
    if transport is None:
        problems.append("no transport layer")
    else:
        protocol = transport.get("protocol")
        if not isinstance(protocol, str):
            problems.append("protocol is missing or not text")
        elif protocol.upper() in TRACKED_PROTOCOLS:
            normalized["protocol"] = protocol.upper()
        else:
            problems.append(f"protocol {_token(protocol)} is not tracked")
    if network is not None:
        normalized["src_ip"], normalized["dst_ip"] = _ip(network.get("src_ip")), _ip(network.get("dst_ip"))
        if None in (normalized["src_ip"], normalized["dst_ip"]):
            problems.append("address is missing or invalid")
    if transport is not None:
        normalized["src_port"], normalized["dst_port"] = _port(transport.get("src_port")), _port(transport.get("dst_port"))
        if None in (normalized["src_port"], normalized["dst_port"]):
            problems.append("port is missing or out of range")
    return problems


def _is_non_first_fragment(record: dict, network: dict | None) -> bool:
    errors = record.get("errors")
    if isinstance(errors, list) and any(isinstance(e, dict) and e.get("type") == "fragment" for e in errors):
        return True
    offset = network.get("frag_offset") if network is not None else None
    return isinstance(offset, int) and not isinstance(offset, bool) and offset > 0


def _ip(value: object) -> str | None:
    # ip_address accepts an int and a zone id such as "fe80::1%eth0", which no flow key can use.
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and PORT_TEXT.fullmatch(value):
        number = int(value)
    else:
        return None
    return number if 0 <= number <= MAX_PORT else None
