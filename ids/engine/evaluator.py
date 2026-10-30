"""Check each kept record against its candidate rules and count the outcome."""

from typing import get_args

from ids.engine.matcher import match
from ids.engine.model import MatchResult, MatchStage, Rule
from ids.engine.repository import RuleRepository
from ids.stages.flow import FlowContext


class Evaluator:
    def __init__(self, repository: RuleRepository) -> None:
        self._repository = repository
        self.records_evaluated = 0
        self.candidate_rules = 0
        self.rejected = dict.fromkeys(get_args(MatchStage), 0)
        self.rule_matches = 0
        self.engine_errors = 0

    def evaluate(self, record: dict, flow: FlowContext | None) -> list[tuple[Rule, MatchResult]]:
        if record.get("processing_action") != "keep":
            return []
        # The counters change only after the whole record succeeds, so an error leaves them consistent.
        try:
            payload = _payload(record)
            candidates = self._repository.candidates(record)
            results = [(rule, match(rule, record, payload, flow)) for rule in candidates]
        except Exception:
            self.engine_errors += 1
            return []
        self.records_evaluated += 1
        self.candidate_rules += len(candidates)
        matches = []
        for rule, result in results:
            if result.matched:
                matches.append((rule, result))
            else:
                self.rejected[result.failed_stage] += 1
        self.rule_matches += len(matches)
        return matches


def _payload(record: dict) -> bytes:
    # With `--payload preview` the record has no payload_hex, and the preview holds the first bytes only.
    for key in ("payload_hex", "payload_preview"):
        try:
            return bytes.fromhex(record[key])
        except (KeyError, TypeError, ValueError):
            continue
    return b""
