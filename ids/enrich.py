"""Run the decoder, the preprocessor, and the flow tracker on one record."""

from collections.abc import Callable

from ids.config import Config
from ids.contract import ENRICHMENT_FIELDS, default_enrichment

STAGE_FIELDS = {
    "decoder": ("decode_status", "decoded"),
    "preprocessor": ("preprocess_status", "processing_action", "reason", "normalized"),
    "flow": ("flow_id", "direction"),
}


class Enricher:
    def __init__(self, config: Config) -> None:
        self._config = config
        # Instance attributes, not module functions, so a test can replace one stage.
        self._decode = _no_result
        self._preprocess = _no_result
        self._track = _no_flow

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
        return []

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


def _fail(output: dict, stage: str, exc: Exception) -> None:
    """Record the error and take back whatever the stage wrote, because it can fail halfway."""
    output["processing_errors"].append(
        {"stage": stage, "type": type(exc).__name__, "message": sanitize(str(exc))}
    )
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


def _no_result(record: dict) -> dict:
    return {}


def _no_flow(record: dict) -> tuple[dict, list[dict]]:
    return {}, []
