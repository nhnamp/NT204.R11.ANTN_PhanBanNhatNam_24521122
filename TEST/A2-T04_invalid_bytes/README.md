# A2-T04 — Invalid bytes

## Purpose

The Decoder must decode a payload as UTF-8 and must not stop on invalid bytes (`DEC-5`). Invalid bytes in a text payload give `partial` with the count of replaced sequences. A payload that is mostly binary gives `partial` with the reason `binary payload` and no `value`. The run must continue after both cases.

## Input

`input.pcap` is a copy of `tests/fixtures/invalid_utf8.pcap`. It holds three TCP packets from `10.0.0.1:40000` or `10.0.0.2:80` to the other side.

| Packet | Direction | Frame length (bytes) | Payload (bytes) | Content |
|---|---|---|---|---|
| 1 | 10.0.0.2:80 → 10.0.0.1:40000 | 140 | 86 | HTTP response, `Content-Length: 22`, body is the bytes `ff fe 80` and ` some readable text` |
| 2 | 10.0.0.1:40000 → 10.0.0.2:4444 | 84 | 30 | `plain text ` + bytes `ff fe 80` + ` more plain text` |
| 3 | 10.0.0.1:40000 → 10.0.0.2:4444 | 118 | 64 | 64 pseudo-random bytes (seed 17) |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T04_invalid_bytes/input.pcap --output TEST/A2-T04_invalid_bytes/output.jsonl
```

The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

## Expected result

The expected values follow from the UTF-8 rules. The bytes `ff` and `fe` never occur in UTF-8. The byte `80` is a continuation byte without a lead byte. So each of the three bytes gives one replacement character. The plan (decision D13) defines the binary rule, and the specification does not. A payload counts as binary when the control bytes plus the invalid sequences are more than a quarter of its length. In packet 3, 4 control bytes and 31 invalid sequences make 35. A quarter of the 64 bytes is 16.

| Packet | Expected item | Expected `value` | `methods` | Reason |
|---|---|---|---|---|
| 1 | `payload`, `partial` | the whole payload with 3 replacement characters | `charset:utf-8` | `invalid UTF-8: 3 invalid sequences replaced` |
| 2 | `payload`, `partial` | the whole payload with 3 replacement characters | `charset:utf-8` | `invalid UTF-8: 3 invalid sequences replaced` |
| 3 | `payload`, `partial` | `null` | none | `binary payload` |

Other fields:
- The run writes 3 events and exits with code 0. The run continues after packets 1 and 2.
- The `decode_status` of all 3 events is `partial`.
- Packet 1 has no `http.body` item. The plan gives a body with only invalid raw bytes no `http.body` item, because the `payload` item already reports the bytes.

## Actual result

`output.jsonl` holds 3 events, and `console.txt` holds the console summary and the exit code 0. All events have `status="ok"`, `preprocess_status="valid"`, and `processing_action="keep"`. The items equal the Expected result table.

| Packet | `app_protocol` | `decode_status` | Item `reason` | Item `value` |
|---|---|---|---|---|
| 1 | `HTTP` | `partial` | `invalid UTF-8: 3 invalid sequences replaced` | text with 3 replacement characters |
| 2 | `UNKNOWN` | `partial` | `invalid UTF-8: 3 invalid sequences replaced` | `plain text ` + 3 replacement characters + ` more plain text` |
| 3 | `UNKNOWN` | `partial` | `binary payload` | `null` |

The flow id of packet 1 is `tcp-cc207a7df611`. Packets 2 and 3 share the flow id `tcp-e0a819cfea96`. The `payload_hex` field keeps the original bytes of every packet.

## Wireshark check

The packets of `input.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison. The Follow TCP Stream view shows packet 1 (86 bytes) in stream 0 and packet 2 (30 bytes) in stream 1. It does not show packet 3, because the sequence numbers of packets 2 and 3 are unrelated, and Wireshark marks packet 3 as `[TCP Previous segment not captured]`. This does not change the packet bytes, so the packet list and the packet bytes are the evidence.

| Packet | Wireshark source → destination | Wireshark Info | Wireshark length | Wireshark TCP payload (bytes) | `length` of the event | `payload_len` of the event | Payload bytes equal | Match |
|---|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.2:80 → 10.0.0.1:40000 | HTTP/1.1 200 OK (text/html) | 140 | 86 | 140 | 86 | yes | yes |
| 2 | 10.0.0.1:40000 → 10.0.0.2:4444 | 40000 → 4444 [PSH, ACK], payload 30 bytes | 84 | 30 | 84 | 30 | yes | yes |
| 3 | 10.0.0.1:40000 → 10.0.0.2:4444 | 40000 → 4444 [PSH, ACK], payload 64 bytes | 118 | 64 | 118 | 64 | yes | yes |

The packet bytes pane of packets 1 and 2 shows the bytes `ff fe 80` at the place that the Input table gives. These bytes are the invalid input of the Decoder.

## Verdict

PASS. The text payloads with invalid bytes give `partial` and the count of replaced sequences. The binary payload gives `partial` with `binary payload` and no value. The run exits with code 0. The packets and the payload bytes equal the Wireshark values.
