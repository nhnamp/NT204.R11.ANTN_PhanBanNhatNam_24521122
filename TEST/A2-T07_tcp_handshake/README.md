# A2-T07 — TCP handshake

## Purpose

The flow tracker must group the three packets of a TCP handshake into one flow, and the flow must end in the state `ESTABLISHED` (`FLOW-5`, `FLOW-6`). The flag counters must count the packets that carry each flag (`FLOW-9`).

## Input

`input.pcap` is a copy of `tests/fixtures/tcp_handshake.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times.

| Packet | Time (s) | Direction | Flags | Frame length (bytes) |
|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 54 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 54 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 |

No packet has a payload.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T07_tcp_handshake/input.pcap --output TEST/A2-T07_tcp_handshake/output.jsonl --flows-output TEST/A2-T07_tcp_handshake/flows.jsonl
```

## Expected result

- The run writes 3 events and 1 flow record, and exits with code 0.
- The 3 events have the same `flow_id`. Packet 1 and packet 3 have `direction="forward"`. Packet 2 has `direction="backward"`.
- The flow has `state="ESTABLISHED"`. The first packet is a SYN, so state `HANDSHAKE` starts. The final ACK moves the state to `ESTABLISHED`.
- `syn_count=2` (the SYN and the SYN/ACK) and `ack_count=2` (the SYN/ACK and the ACK). `fin_count=0` and `rst_count=0`.
- `packet_count=3`, with 2 forward packets and 1 backward packet. `byte_count=162`: 3 × 54 bytes. The forward byte count is 108 and the backward byte count is 54.
- `duration=1.0` and `end_reason="end_of_input"`.
- `application_protocol="HTTP"`. No packet has a payload, so the port decides: the detector maps port 80 to HTTP.
- The flow id depends only on the 5-tuple and the start time. Other cases that use the same 5-tuple and the same start time have the same id.

## Actual result

`output.jsonl` holds 3 events, `flows.jsonl` holds 1 flow record, and `console.txt` holds the console summary and the exit code 0.

| Field of the flow record | Value |
|---|---|
| `flow_id` | `tcp-5f8ec36d79cc` |
| `protocol`, `application_protocol` | `TCP`, `HTTP` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:80` |
| `start_time`, `last_seen`, `duration` | 1758441600.0, 1758441601.0, 1.0 |
| `packet_count`, `byte_count` | 3, 162 |
| forward `packet_count`, `byte_count` | 2, 108 |
| backward `packet_count`, `byte_count` | 1, 54 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count` | 2, 2, 0, 0 |
| `state` | `ESTABLISHED` |
| `end_reason` | `end_of_input` |

The events hold the same `flow_id`. The directions are `forward`, `backward`, `forward`. All events have `preprocess_status="valid"` and `processing_action="keep"`.

## Wireshark check

The owner opened `input.pcap` in Wireshark.

**Packet list.** The flags of the three packets are `[SYN]`, `[SYN, ACK]`, and `[ACK]`, in this order.

**Statistics → Conversations → TCP.** Wireshark shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 80 |
| Packets | 3 |
| Packets A → B, Packets B → A | 2, 1 |
| Bytes | 162 |
| Bytes A → B, Bytes B → A | 108, 54 |
| Duration | 1 |

The comparison with the flow record:

| Item | Flow record | Wireshark |
|---|---|---|
| Number of flows | 1 | 1 conversation |
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:80` | 10.0.0.1:40000, 10.0.0.2:80 |
| Flags in order | SYN, SYN/ACK, ACK (events) | `[SYN]`, `[SYN, ACK]`, `[ACK]` |
| `packet_count` | 3 | 3 |
| Forward / backward packets | 2 / 1 | 2 / 1 |
| `byte_count` | 162 | 162 |
| Forward / backward bytes | 108 / 54 | 108 / 54 |
| `duration` | 1.0 | 1 |

Wireshark does not show the logical state. The packet flags follow the rule for `ESTABLISHED`: a SYN starts `HANDSHAKE`, and the ACK after the SYN/ACK moves the flow to `ESTABLISHED`. The counters follow from the flags: 2 packets carry SYN and 2 packets carry ACK.

## Verdict

PASS. The flow record matches the Wireshark conversation in endpoints, packet counts, byte counts, and duration. The packet flags match the flags in the events, and the state follows the rule for the handshake.
