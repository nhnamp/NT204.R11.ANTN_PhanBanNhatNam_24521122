# TC-01 — TCP handshake

## Purpose

The parser must identify the three steps of a TCP handshake: SYN, SYN/ACK, and ACK.

## Input

`input.pcap` is a copy of `tests/fixtures/tcp_handshake.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times.

| Packet | Direction | Flags | Seq | Ack |
|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 1000 | 0 |
| 2 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 5000 | 1001 |
| 3 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 1001 | 5001 |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-01_tcp_handshake/input.pcap --output TEST/TC-01_tcp_handshake/output.jsonl
```

## Expected result

- The run writes 3 events and exits with code 0.
- `transport.handshake` is `"SYN"`, `"SYN/ACK"`, and `"ACK"`, in this order.
- Every event has `status="ok"`, `payload_len=0`, and no errors.
- Every event has `app_protocol="HTTP"` from the port hint only: `detection.method="port"`, `detection.confidence="low"` (R5.5). The payload is empty, so no payload rule can run.

## Actual result

`output.jsonl` holds 3 events. `console.txt` holds the console summary and the exit code 0.

| `packet_id` | `transport.flags` | `transport.flags_str` | `seq` | `ack` | `transport.handshake` | `status` | `app_protocol` | `detection` |
|---|---|---|---|---|---|---|---|---|
| 1 | `["SYN"]` | `S` | 1000 | 0 | `SYN` | `ok` | `HTTP` | `port`, `low`, `port_hint` |
| 2 | `["SYN", "ACK"]` | `SA` | 5000 | 1001 | `SYN/ACK` | `ok` | `HTTP` | `port`, `low`, `port_hint` |
| 3 | `["ACK"]` | `A` | 1001 | 5001 | `ACK` | `ok` | `HTTP` | `port`, `low`, `port_hint` |

Packet 2 gets the hint from its source port 80, because the detector checks the destination port first and then the source port.

The events hold absolute sequence numbers. Wireshark shows relative numbers by default, so packet 1 shows `Seq=0` there.

Wireshark shows the same three steps: `[SYN]`, `[SYN, ACK]`, and `[ACK]`. Its raw sequence and acknowledgment numbers match the table.

## Retest after the detector (P5, R5.9)

The first run of this case had no Application Protocol Detector, so every event had `app_protocol="UNKNOWN"` and `detection=null`. The retest changes only these two fields in all 3 events. All network and transport fields are the same as in the first run.

## Retest after Assignment 02

The retest reruns the command of this case with the program of Assignment 02. The base fields are unchanged: every event has the same values and the same key order as in the committed output before the retest. The retest adds ten keys to each event: `payload_hex`, `decode_status`, `decoded`, `preprocess_status`, `processing_action`, `reason`, `normalized`, `flow_id`, `direction`, and `processing_errors`. `console.txt` shows the new summary lines.

New values in this case:

- `decode_status` is `not_applicable` and `decoded` is `[]` for all 3 events, because nothing needs decoding.
- `preprocess_status` is `valid`, `processing_action` is `keep`, and `reason` is `null` for all 3 events.
- All events have the `flow_id` `tcp-5f8ec36d79cc`, and `direction` is `forward`, `backward`, `forward`.
- `processing_errors` is `[]`.
- `normalized.tcp_flags` follows the TCP flags of each event (`SYN`, then `SYN` and `ACK`, then `ACK`), and `normalized.app_protocol` is `HTTP` from the port hint.

The tables above describe the base fields and stay valid. The field `errors` is the parser list of Assignment 01. The new list `processing_errors` is separate. No Wireshark check is repeated, because no base field changed.

## Verdict

PASS.
