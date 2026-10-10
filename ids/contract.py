"""Field names and value sets that the enrichment stages share with their tests."""

from typing import Literal, get_args

BASE_FIELDS = (
    "packet_id",
    "timestamp",
    "timestamp_iso",
    "source",
    "length",
    "link_type",
    "network",
    "transport",
    "app_protocol",
    "detection",
    "application",
    "payload_len",
    "payload_preview",
    "status",
    "errors",
)

# The pipeline writes this field, so it is not an enrichment field: the replay rule keeps it, and the evidence check removes it.
PAYLOAD_FIELD = "payload_hex"

ENRICHMENT_FIELDS = (
    "decode_status",
    "decoded",
    "preprocess_status",
    "processing_action",
    "reason",
    "normalized",
    "flow_id",
    "direction",
    "processing_errors",
)

DecodeStatus = Literal["ok", "partial", "failed", "not_applicable"]
PreprocessStatus = Literal["valid", "partial", "invalid"]
ProcessingAction = Literal["keep", "skip_flow"]
ErrorStage = Literal["input", "decoder", "preprocessor", "flow", "output"]
TypedError = Literal["invalid_record", "limit"]

DECODE_STATUSES = get_args(DecodeStatus)
PREPROCESS_STATUSES = get_args(PreprocessStatus)
PROCESSING_ACTIONS = get_args(ProcessingAction)
ERROR_STAGES = get_args(ErrorStage)
TYPED_ERRORS = get_args(TypedError)
