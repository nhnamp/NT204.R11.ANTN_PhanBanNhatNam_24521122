# A2-T06 — Missing field

## Purpose

An event that lacks a field that is not mandatory must give `null` and `[]` in a consistent way, and must not raise an exception (`PRE-4`). Only the timestamp is mandatory.

## Input

`input.jsonl` is a copy of `tests/fixtures/events/missing_fields.jsonl`. A PCAP file cannot produce an event with a missing field, so the input is an events file.

| Record | Fields that the record holds | Fields that the record lacks |
|---|---|---|
| 1 | `timestamp`, `network` (IPs), `transport` (protocol, ports, flags) | `application`, `detection`, `errors`, `payload_preview`, `length`, `payload_len`, `status`, `app_protocol` |
| 2 | `timestamp` | everything else |

## Command

Run the command from the repository root.

```bash
python main.py --events TEST/A2-T06_missing_field/input.jsonl --output TEST/A2-T06_missing_field/output.jsonl
```

The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

## Expected result

- The run writes 2 events and exits with code 0. No traceback appears.
- The output keeps the fields of the input and does not add base fields. It adds only the enrichment fields.
- Record 1 is `valid` with `processing_action="keep"` and `reason=null`, because the timestamp and the flow fields are usable. A missing optional field does not change the status.
- In `normalized`, record 1 gives `length`, `payload_len`, `detection_method`, `host`, `path`, and `query` as `null`. It gives `domains` as `[]`, `headers` as `{}`, and `app_protocol` as `UNKNOWN`. The IPs, the ports, the protocol, and the flags come from the input.
- Record 1 has a `flow_id`, because its flow fields are usable.
- Record 2 is `partial` with `skip_flow` and the reason `no network layer; no transport layer`. It has no `flow_id`.
- In `normalized`, record 2 keeps the timestamp. The protocol, the IPs, the ports, and every other optional key are `null`, and the lists are `[]`.
- Both events have `decode_status="not_applicable"`, `decoded=[]`, and `processing_errors=[]`.

## Actual result

`output.jsonl` holds 2 events, and `console.txt` holds the console summary and the exit code 0. The values equal the Expected result.

| Record | `preprocess_status` | `processing_action` | `reason` | `flow_id` | `direction` |
|---|---|---|---|---|---|
| 1 | `valid` | `keep` | `null` | `tcp-58d9489f0581` | `forward` |
| 2 | `partial` | `skip_flow` | `no network layer; no transport layer` | `null` | `null` |

The `normalized` object of record 1 has the `null` values and the empty list and object as the Expected result lists. The `normalized` object of record 2 has the timestamp (`1758441600.0`, `2025-09-21T08:00:00+00:00`) and no other value.

In the console summary, `other: 2` counts the records without a `status`. A record without a `status` counts as `ok` for the preprocessor, so record 1 is still `valid`.

## Wireshark check

This case has no Wireshark part. The input is an events file, not a capture file, and Wireshark cannot open it. The expected values follow from the plan (R4.2) and the specification (`PRE-4`).

## Verdict

PASS. The missing optional fields give `null` and `[]`. The run raises no exception. A record with only a timestamp gives `partial` and `skip_flow`, and a record with usable flow fields stays `valid` and joins a flow.
