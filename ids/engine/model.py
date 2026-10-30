"""The internal rule object, the match result, and the rule match record."""

from dataclasses import dataclass, fields, is_dataclass
from ipaddress import IPv4Network
from typing import Literal

from ids.stages.preprocessor import TCP_FLAGS

Protocol = Literal["tcp", "udp", "ip"]
Direction = Literal["->", "<>"]
RuleStatus = Literal["valid", "invalid", "unsupported", "disabled"]
# The matcher runs the stages in this order and stops at the first one that fails.
MatchStage = Literal["header", "flow", "packet", "content"]


@dataclass(frozen=True)
class PortRange:
    """An inclusive port range. A single port has low equal to high."""

    low: int
    high: int


@dataclass(frozen=True)
class Content:
    """One `content` option and the modifiers after it. `None` means that the rule does not set the modifier."""

    text: str
    pattern: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass(frozen=True)
class FlowOption:
    """`None` means that the rule does not check this part of the flow."""

    direction: Literal["to_server", "to_client"] | None = None
    established: bool | None = None


@dataclass(frozen=True)
class FlagsOption:
    """The flag names are those of `normalized.tcp_flags`. An empty set is `flags:0`."""

    flags: frozenset[str]
    modifier: Literal["", "+", "*", "!"] = ""


@dataclass(frozen=True)
class DsizeOption:
    """`upper` is set only for the range `value<>upper`, which includes both limits."""

    operator: Literal["=", ">", "<", "<>"]
    value: int
    upper: int | None = None


@dataclass(frozen=True)
class Rule:
    """One valid rule. An address or a port of `None` means `any`."""

    sid: int
    rev: int
    msg: str
    action: Literal["alert"]
    protocol: Protocol
    src_ip: IPv4Network | None
    src_port: PortRange | None
    direction: Direction
    dst_ip: IPv4Network | None
    dst_port: PortRange | None
    contents: tuple[Content, ...] = ()
    flow: FlowOption | None = None
    flags: FlagsOption | None = None
    dsize: DsizeOption | None = None
    classtype: str | None = None
    priority: int | None = None
    origin: str = ""

    def to_dict(self) -> dict:
        return _jsonable(self)


@dataclass(frozen=True)
class ParsedRule:
    """One rule line after the parser, as the rules report writes it. `rule` is set for `valid` and `disabled`."""

    file: str
    line: int
    text: str
    status: RuleStatus
    reason: str | None
    rule: Rule | None

    def to_dict(self) -> dict:
        return _jsonable(self)


@dataclass(frozen=True)
class MatchedItem:
    """One option that matched. `position` is the start of a content match in the buffer."""

    keyword: str
    value: str
    position: int | None = None


@dataclass(frozen=True)
class MatchResult:
    sid: int
    matched: bool
    failed_stage: MatchStage | None = None
    items: tuple[MatchedItem, ...] = ()

    @property
    def verdict(self) -> Literal["MATCH", "NO_MATCH"]:
        return "MATCH" if self.matched else "NO_MATCH"


@dataclass(frozen=True)
class RuleMatch:
    """The record for one rule that matched one packet record. `packet_id` and `source` link it to the event."""

    timestamp: float
    timestamp_iso: str
    sid: int
    rev: int
    msg: str
    classtype: str | None
    priority: int | None
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    application_protocol: str
    flow_id: str | None
    direction: str | None
    flow_state: str | None
    packet_id: int | None
    source: str | None
    matched: tuple[MatchedItem, ...]

    def to_dict(self) -> dict:
        return _jsonable(self)


def _jsonable(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {item.name: _jsonable(getattr(value, item.name)) for item in fields(value)}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(value, key=TCP_FLAGS.index)
    if isinstance(value, IPv4Network):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value
