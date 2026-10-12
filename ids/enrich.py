"""Run the decoder, the preprocessor, and the flow tracker on one record."""

from collections.abc import Callable
from functools import partial

from ids.config import Config
from ids.contract import ENRICHMENT_FIELDS, TYPED_ERRORS, default_enrichment
from ids.stages.decoder import decode_record
from ids.stages.flow import FlowTracker
from ids.stages.preprocessor import preprocess_record

STAGE_FIELDS = {
    "decoder": ("decode_status", "decoded"),
    "preprocessor": ("preprocess_status", "processing_action", "reason", "normalized"),
    "flow": ("flow_id", "direction"),
}


class Enricher:
    def __init__(self, config: Config) -> None:
        self._config = config
        # Instance attributes, not module functions, so a test can replace one stage.
        self._decode = partial(decode_record, payload_limit=config.payload_limit)
        self._preprocess = preprocess_record
        self._tracker = FlowTracker(tcp_timeout=config.tcp_timeout, udp_timeout=config.udp_timeout)
        self._track = self._update_flow

    def process(
        self, record: dict, input_errors: list[dict] | None = None
    ) -> tuple[dict | None, list[dict]]:
        """Return the output record and the flows that this record caused to leave the table."""
        # A replayed record holds old enrichment fields. Removing them first puts the new ones
        # after the base fields in one fixed order, wherever the old ones stood.
        output = {key: value for key, value in record.items() if key not in ENRICHMENT_FIELDS}
        output.update(default_enrichment())
        output["processing_errors"].extend(input_errors or [])

        self._run_stage(output, "decoder", self._decode)
        if not self._run_stage(output, "preprocessor", self._preprocess):
            output["reason"] = "preprocessor failed"
        if self._config.unknown == "drop" and _is_droppable(output):
            return None, []
        exported: list[dict] = []
        if output["processing_action"] == "keep":
            try:
                result, exported = self._track(output)
                _apply(output, result)
            # One bad record must not end the run.
            except Exception as exc:
                # `exported` keeps the flows that already left the table: they must not be lost.
                _fail(output, "flow", exc)
        return output, exported

    def flush(self) -> list[dict]:
        return self._tracker.flush()

    def _update_flow(self, record: dict) -> tuple[dict, list[dict]]:
        flow_id, direction, exported = self._tracker.update(record["normalized"])
        return {"flow_id": flow_id, "direction": direction}, exported

    def _run_stage(self, output: dict, stage: str, run: Callable[[dict], dict]) -> bool:
        """Merge the result of one stage. A failure keeps the defaults and records the error."""
        try:
            _apply(output, run(output))
        # One bad record must not end the run.
        except Exception as exc:
            _fail(output, stage, exc)
            return False
        return True


def sanitize(text: str) -> str:
    """Replace what UTF-8 cannot encode, such as a lone surrogate, so the writer cannot fail."""
    return text.encode("utf-8", "replace").decode("utf-8")


def error_entry(stage: str, exc: Exception) -> dict:
    return {"stage": stage, "type": type(exc).__name__, "message": sanitize(str(exc))}


def input_failure(source: str, exc: Exception) -> tuple[dict, list[dict]]:
    """Stand in for an event that could not become a record, so the loop still writes a line."""
    return {"source": sanitize(source)}, [error_entry("input", exc)]


def fallback_record(record: dict, exc: Exception, *, keep_base: bool) -> dict:
    """Build the record to write when the full record failed to write.

    The first fallback keeps the base fields. The last one keeps only a sanitized source,
    so it cannot fail.
    """
    if keep_base:
        output = {key: value for key, value in record.items() if key not in ENRICHMENT_FIELDS}
    else:
        output = {"source": sanitize(str(record.get("source", "")))}
    output.update(default_enrichment())
    output["reason"] = "record could not be written"
    output["processing_errors"].append(error_entry("output", exc))
    return output


def _is_droppable(output: dict) -> bool:
    """Say if the `--unknown drop` policy removes the record.

    An entry with an exception class name is a bug. A record that carries one is written, so
    the bug stays visible.
    """
    unusable = output.get("status") == "unsupported" or output["preprocess_status"] == "invalid"
    return unusable and all(error["type"] in TYPED_ERRORS for error in output["processing_errors"])


def _fail(output: dict, stage: str, exc: Exception) -> None:
    """Record the error and take back whatever the stage wrote, because it can fail halfway."""
    output["processing_errors"].append(error_entry(stage, exc))
    defaults = default_enrichment()
    for field in STAGE_FIELDS[stage]:
        output[field] = defaults[field]


def _apply(output: dict, result: dict) -> None:
    unknown = result.keys() - set(ENRICHMENT_FIELDS)
    if unknown:
        raise KeyError(sorted(unknown))
    for key, value in result.items():
        if key == "processing_errors":
            output[key].extend(value)
        else:
            output[key] = value
