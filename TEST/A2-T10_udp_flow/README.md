# A2-T10 — UDP query and response

## Purpose

The flow tracker must group a UDP query and its response into one bidirectional flow (`FLOW-2`, `FLOW-7`). The flow record must hold the packet and byte counts of both directions (`FLOW-9`).

## Input

`input.pcap` is a copy of `tests/fixtures/dns_udp_flow.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times.

| Packet | Time (s) | Direction | Frame length (bytes) | Content |
|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:53 | 71 | DNS query, A record for `example.com` |
| 2 | 0.5 | 10.0.0.2:53 → 10.0.0.1:40000 | 98 | DNS response with one A record |

The response uses the reversed 5-tuple of the query.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T10_udp_flow/input.pcap --output TEST/A2-T10_udp_flow/output.jsonl --flows-output TEST/A2-T10_udp_flow/flows.jsonl
```

## Expected result

- The run writes 2 events and 1 flow record, and exits with code 0.
- Both events have the same `flow_id`. Packet 1 has `direction="forward"` and packet 2 has `direction="backward"`.
- The flow has `packet_count=2`, with 1 forward packet and 1 backward packet.
- `byte_count` is the sum of the base `length` of the two events: 71 + 98 = 169. The forward byte count is 71 and the backward byte count is 98. `length` is the captured frame length, with the 14-byte Ethernet header.
- `application_protocol="DNS"`, `duration=0.5`, and `end_reason="end_of_input"`.
- The TCP fields (`syn_count`, `ack_count`, `fin_count`, `rst_count`, `state`) are `null`, because UDP has no connection state.

## Actual result

`output.jsonl` holds 2 events, `flows.jsonl` holds 1 flow record, and `console.txt` holds the console summary and the exit code 0.

| Field of the flow record | Value |
|---|---|
| `flow_id` | `udp-499d79bf977b` |
| `protocol`, `application_protocol` | `UDP`, `DNS` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:53` |
| `start_time`, `last_seen`, `duration` | 1758441600.0, 1758441600.5, 0.5 |
| `packet_count`, `byte_count` | 2, 169 |
| forward `packet_count`, `byte_count` | 1, 71 |
| backward `packet_count`, `byte_count` | 1, 98 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state` | `null` |
| `end_reason` | `end_of_input` |

The events hold the same `flow_id`. Packet 1 is `forward` and packet 2 is `backward`. Both events have `preprocess_status="valid"` and `processing_action="keep"`.

## Wireshark check

The owner opened `input.pcap` in Wireshark and read Statistics → Conversations → UDP. Wireshark shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 53 |
| Packets | 2 |
| Packets A → B, Packets B → A | 1, 1 |
| Bytes | 169 |
| Bytes A → B, Bytes B → A | 71, 98 |
| Duration | 0.5 |

The comparison with the flow record:

| Item | Flow record | Wireshark |
|---|---|---|
| Number of flows | 1 | 1 conversation |
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:53` | 10.0.0.1:40000, 10.0.0.2:53 |
| `packet_count` | 2 | 2 |
| Forward / backward packets | 1 / 1 | 1 / 1 |
| `byte_count` | 169 | 169 |
| Forward / backward bytes | 71 / 98 | 71 / 98 |
| `duration` | 0.5 | 0.5 |

The Wireshark byte counts equal the frame lengths in the Input table (71 and 98).

## Verdict

PASS. The flow record matches the Wireshark conversation in endpoints, packet counts, byte counts, and duration.
