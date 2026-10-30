import re
from ipaddress import IPv4Network

from ids.engine.model import (
    Content,
    DsizeOption,
    FlagsOption,
    FlowOption,
    ParsedRule,
    PortRange,
    Rule,
)

FLAG_NAMES = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG", "C": "CWR", "E": "ECE"}
OTHER_ACTIONS = ("log", "pass", "drop", "reject", "sdrop", "activate", "dynamic")
SINGLE_OPTIONS = ("sid", "rev", "msg", "classtype", "priority", "flow", "flags", "dsize")
CONTENT_MODIFIERS = ("nocase", "offset", "depth", "distance", "within")
NUMBER = re.compile(r"-?[0-9]{1,10}")
DSIZE = re.compile(r"(?:(?P<op>[<>]) *(?P<one>[0-9]{1,10})|(?P<low>[0-9]{1,10}) *<> *(?P<high>[0-9]{1,10})|(?P<exact>[0-9]{1,10}))")


class _Reject(Exception):
    def __init__(self, status: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _invalid(reason: str) -> _Reject:
    return _Reject("invalid", reason)


def _unsupported(reason: str) -> _Reject:
    return _Reject("unsupported", reason)


def parse_rule(file: str, line: int, text: str) -> ParsedRule:
    """Parse one rule line. This function never raises."""
    try:
        rule = _parse(f"{file}:{line}", text.strip())
    except _Reject as reject:
        return ParsedRule(file, line, text, reject.status, reject.reason, None)
    return ParsedRule(file, line, text, "valid", None, rule)


def _parse(origin: str, text: str) -> Rule:
    start = text.find("(")
    if start < 0 or not text.endswith(")"):
        raise _invalid("a rule needs a header and options in parentheses")
    header = _parse_header(text[:start].split())
    options = _parse_options(text[start + 1 : -1])
    return Rule(
        action="alert",
        protocol=header["protocol"],
        src_ip=header["src_ip"],
        src_port=header["src_port"],
        direction=header["direction"],
        dst_ip=header["dst_ip"],
        dst_port=header["dst_port"],
        origin=origin,
        **options,
    )


def _parse_header(fields: list[str]) -> dict:
    if len(fields) != 7:
        if any(mark in " ".join(fields) for mark in "[,"):
            raise _unsupported("lists in the header")
        raise _invalid(f"the header needs 7 fields, found {len(fields)}")
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = fields
    if action != "alert":
        if action in OTHER_ACTIONS:
            raise _unsupported(f"action {action}")
        raise _invalid(f"unknown action {action}")
    if protocol == "icmp":
        raise _unsupported("protocol icmp")
    if protocol not in ("tcp", "udp", "ip"):
        raise _invalid(f"unknown protocol {protocol}")
    if direction not in ("->", "<>"):
        raise _invalid(f"bad direction {direction}")
    header = {
        "protocol": protocol,
        "direction": direction,
        "src_ip": _parse_address(src_ip),
        "dst_ip": _parse_address(dst_ip),
        "src_port": _parse_port(src_port),
        "dst_port": _parse_port(dst_port),
    }
    if protocol == "ip" and (header["src_port"] or header["dst_port"]):
        raise _invalid("an ip rule needs any as port")
    return header


def _check_variable_syntax(value: str) -> None:
    if value.startswith("$"):
        raise _unsupported(f"variable {value}")
    if value.startswith("!"):
        raise _unsupported(f"negation {value}")
    if "[" in value or "," in value:
        raise _unsupported(f"list {value}")


def _parse_address(value: str) -> IPv4Network | None:
    if value == "any":
        return None
    _check_variable_syntax(value)
    try:
        return IPv4Network(value, strict=False)
    except ValueError:
        raise _invalid(f"bad address {value}") from None


def _parse_port(value: str) -> PortRange | None:
    if value == "any":
        return None
    _check_variable_syntax(value)
    low, colon, high = value.partition(":")
    parts = [part for part in (low, high) if part]
    if not parts or not all(re.fullmatch(r"[0-9]{1,5}", part) for part in parts) or (colon and ":" in high):
        raise _invalid(f"bad port {value}")
    if any(int(part) > 65535 for part in parts):
        raise _invalid(f"port above 65535 in {value}")
    if not colon:
        return PortRange(int(low), int(low))
    port_range = PortRange(int(low) if low else 0, int(high) if high else 65535)
    if port_range.low > port_range.high:
        raise _invalid(f"port range {value} is reversed")
    return port_range


def _split_options(text: str) -> list[str]:
    tokens, current, quoted, index = [], [], False, 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            current.append(text[index : index + 2])
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            tokens.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    if quoted:
        raise _invalid("a quote is not closed")
    tokens.append("".join(current))
    return [token.strip() for token in tokens if token.strip()]


def _parse_options(text: str) -> dict:
    seen: set[str] = set()
    values: dict = {}
    contents: list[dict] = []
    for token in _split_options(text):
        key, _, value = token.partition(":")
        key, value = key.strip(), value.strip()
        if key in SINGLE_OPTIONS:
            if key in seen:
                raise _invalid(f"option {key} appears twice")
            seen.add(key)
        if key == "content":
            contents.append(_parse_content(value))
        elif key in CONTENT_MODIFIERS:
            _add_modifier(contents, key, value)
        elif key in SINGLE_OPTIONS:
            values[key] = _SINGLE_PARSERS[key](value)
        else:
            raise _unsupported(f"keyword {key}")
    for required in ("sid", "msg"):
        if required not in values:
            raise _invalid(f"missing {required}")
    values.setdefault("rev", 1)
    values["contents"] = tuple(_finish_content(item) for item in contents)
    return values


def _number(value: str, name: str, negative: bool = False) -> int:
    if not NUMBER.fullmatch(value) or (value.startswith("-") and not negative):
        raise _invalid(f"{name} needs a number, found {value!r}")
    return int(value)


def _unquote(value: str, name: str) -> str:
    if len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
        raise _invalid(f"{name} needs a quoted string")
    return value[1:-1]


def _parse_content(value: str) -> dict:
    if value.startswith("!"):
        raise _unsupported("negated content")
    inner = _unquote(value, "content")
    pattern, hex_mode, index = bytearray(), False, 0
    hex_digits = ""
    while index < len(inner):
        char = inner[index]
        if char == "|":
            if hex_mode and hex_digits:
                raise _invalid("a hex run needs two digits for each byte")
            hex_mode = not hex_mode
        elif hex_mode:
            if char != " ":
                hex_digits += char
                if len(hex_digits) == 2:
                    if not re.fullmatch(r"[0-9A-Fa-f]{2}", hex_digits):
                        raise _invalid(f"bad hex digits {hex_digits!r}")
                    pattern.append(int(hex_digits, 16))
                    hex_digits = ""
        else:
            if char == "\\":
                char = inner[index + 1 : index + 2]
                if char not in ('"', ";", "\\"):
                    raise _invalid("bad escape in content")
                index += 1
            elif char == '"':
                raise _invalid("a quote in content needs an escape")
            try:
                pattern += char.encode("utf-8")
            except UnicodeEncodeError:
                raise _invalid("content has a character that is not text") from None
        index += 1
    if hex_mode:
        raise _invalid("a hex run is not closed")
    if not pattern:
        raise _invalid("content is empty")
    return {"text": inner, "pattern": bytes(pattern), "modifiers": {}}


def _add_modifier(contents: list[dict], key: str, value: str) -> None:
    if not contents:
        raise _invalid(f"{key} comes before any content")
    modifiers = contents[-1]["modifiers"]
    if key in modifiers:
        raise _invalid(f"{key} appears twice for one content")
    if key == "nocase":
        if value:
            raise _invalid("nocase takes no value")
        modifiers[key] = True
    else:
        modifiers[key] = _number(value, key, negative=key == "distance")
        if key in ("offset", "depth", "within") and modifiers[key] < 0:
            raise _invalid(f"{key} cannot be negative")


def _finish_content(item: dict) -> Content:
    modifiers, pattern = item["modifiers"], item["pattern"]
    if ("offset" in modifiers or "depth" in modifiers) and ("distance" in modifiers or "within" in modifiers):
        raise _invalid("offset or depth cannot combine with distance or within")
    for name in ("depth", "within"):
        if name in modifiers and modifiers[name] < len(pattern):
            raise _invalid(f"{name} is smaller than the pattern")
    return Content(item["text"], pattern, **modifiers)


def _parse_sid(value: str) -> int:
    return _number(value, "sid")


def _parse_rev(value: str) -> int:
    return _number(value, "rev")


def _parse_msg(value: str) -> str:
    if value.startswith('"'):
        value = _unquote(value, "msg")
    if not value:
        raise _invalid("msg is empty")
    return re.sub(r"\\(.)", r"\1", value)


def _parse_classtype(value: str) -> str:
    if not value:
        raise _invalid("classtype is empty")
    return value


def _parse_priority(value: str) -> int:
    return _number(value, "priority")


def _parse_flow(value: str) -> FlowOption:
    direction, established = None, None
    for name in (part.strip() for part in value.split(",")):
        if name in ("to_server", "to_client"):
            if direction not in (None, name):
                raise _invalid("flow has both to_server and to_client")
            direction = name
        elif name in ("established", "not_established"):
            if established not in (None, name == "established"):
                raise _invalid("flow has both established and not_established")
            established = name == "established"
        elif name:
            raise _unsupported(f"flow value {name}")
        else:
            raise _invalid("flow has an empty value")
    return FlowOption(direction, established)


def _parse_flags(value: str) -> FlagsOption:
    if "," in value:
        raise _unsupported("flags with a mask")
    modifier = ""
    if value[:1] in ("+", "*", "!"):
        modifier, value = value[0], value[1:]
    elif value[-1:] in ("+", "*", "!"):
        modifier, value = value[-1], value[:-1]
    if not value:
        raise _invalid("flags is empty")
    bad = sorted({char for char in value if char not in FLAG_NAMES and char not in "012"})
    if bad:
        raise _invalid(f"bad flag character {bad[0]!r}")
    if "1" in value or "2" in value:
        raise _unsupported("legacy flags 1 and 2")
    if "0" in value:
        if value != "0":
            raise _invalid("flag 0 cannot combine with other flags")
        return FlagsOption(frozenset(), modifier)
    return FlagsOption(frozenset(FLAG_NAMES[char] for char in value), modifier)


def _parse_dsize(value: str) -> DsizeOption:
    match = DSIZE.fullmatch(value)
    if not match:
        raise _invalid(f"bad dsize {value!r}")
    if match["op"]:
        return DsizeOption(match["op"], int(match["one"]))
    if match["exact"]:
        return DsizeOption("=", int(match["exact"]))
    low, high = int(match["low"]), int(match["high"])
    if low > high:
        raise _invalid("dsize range is reversed")
    return DsizeOption("<>", low, high)


_SINGLE_PARSERS = {
    "sid": _parse_sid,
    "rev": _parse_rev,
    "msg": _parse_msg,
    "classtype": _parse_classtype,
    "priority": _parse_priority,
    "flow": _parse_flow,
    "flags": _parse_flags,
    "dsize": _parse_dsize,
}
