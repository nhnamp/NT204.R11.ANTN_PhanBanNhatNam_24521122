from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from ids.engine.model import ParsedRule, Rule


class _ProtocolIndex:
    def __init__(self) -> None:
        self.by_port: dict[int, list[Rule]] = defaultdict(list)
        self.wildcard: list[Rule] = []


class RuleRepository:
    """`rejected` holds the duplicate and disabled entries, ready for the rules report."""

    def __init__(self, parsed_rules: Iterable[ParsedRule], disabled_sids: Iterable[int] = ()) -> None:
        disabled = set(disabled_sids)
        self.rejected: list[ParsedRule] = []
        self._rules: dict[int, Rule] = {}
        self._ip_rules: list[Rule] = []
        self._index = {"tcp": _ProtocolIndex(), "udp": _ProtocolIndex()}
        seen: set[int] = set()
        for parsed in parsed_rules:
            rule = parsed.rule
            if rule is None or parsed.status != "valid":
                continue
            if rule.sid in seen:
                self.rejected.append(replace(parsed, status="invalid", reason=f"duplicate sid {rule.sid}", rule=None))
            elif rule.sid in disabled:
                seen.add(rule.sid)
                self.rejected.append(replace(parsed, status="disabled", reason=f"sid {rule.sid} is in disabled_sids"))
            else:
                seen.add(rule.sid)
                self._add(rule)

    def __len__(self) -> int:
        return len(self._rules)

    def _add(self, rule: Rule) -> None:
        self._rules[rule.sid] = rule
        if rule.protocol == "ip":
            self._ip_rules.append(rule)
            return
        index = self._index[rule.protocol]
        ports = [port.low for port in self._single_ports(rule)]
        if not ports:
            index.wildcard.append(rule)
        for port in ports:
            index.by_port[port].append(rule)

    @staticmethod
    def _single_ports(rule: Rule) -> list:
        """The ports a record must show for the rule to match. An empty list means that no single port decides."""
        def single(port):
            return port is not None and port.low == port.high

        if rule.direction == "->":
            return [rule.dst_port] if single(rule.dst_port) else []
        return [port for port in (rule.src_port, rule.dst_port) if single(port)]

    def candidates(self, record: dict) -> list[Rule]:
        normalized = record.get("normalized") or {}
        protocol = str(normalized.get("protocol")).lower()
        if protocol not in self._index:
            return []
        index = self._index[protocol]
        found = {rule.sid: rule for rule in index.wildcard}
        found.update((rule.sid, rule) for rule in self._ip_rules)
        for port in {normalized.get("src_port"), normalized.get("dst_port")}:
            for rule in index.by_port.get(port, ()):
                found[rule.sid] = rule
        return [found[sid] for sid in sorted(found)]
