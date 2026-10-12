# A2-T12 — Idle timeout

## Purpose

A flow that sees no packet for longer than the idle timeout must leave the flow table before the end of the input (`FLOW-8`). A new packet on the same 5-tuple after that must start a new flow with another `flow_id`. The input has large gaps in packet time, so the timeout fires without a long wait.

## Input

`input.pcap` is a copy of `tests/fixtures/idle_timeout.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with the times of `FIXTURE_TIMES`.

Three DNS exchanges over UDP. Each exchange is a query and its response. The response uses the reversed 5-tuple of the query.

| Packet | Time (s) | Direction | Frame length (bytes) | Content |
|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:53 | 71 | DNS query for `example.com` |
| 2 | 0.5 | 10.0.0.2:53 → 10.0.0.1:40000 | 98 | DNS response |
| 3 | 100.0 | 10.0.0.1:40001 → 10.0.0.2:53 | 71 | DNS query for `example.com` |
| 4 | 100.5 | 10.0.0.2:53 → 10.0.0.1:40001 | 98 | DNS response |
| 5 | 200.0 | 10.0.0.1:40000 → 10.0.0.2:53 | 71 | DNS query for `example.com` |
| 6 | 200.5 | 10.0.0.2:53 → 10.0.0.1:40000 | 98 | DNS response |

Packets 1, 2, 5, and 6 use the same 5-tuple. Packets 3 and 4 use another client port.

## Command

Run the command from the repository root. The run uses the default idle timeout for UDP: 30 seconds of packet time.

```bash
python main.py --pcap TEST/A2-T12_idle_timeout/input.pcap --output TEST/A2-T12_idle_timeout/output.jsonl --flows-output TEST/A2-T12_idle_timeout/flows.jsonl
```

## Expected result

- The run writes 6 events and 3 flow records, and exits with code 0.
- A flow expires when the time of the newest packet minus the time of its last packet is more than 30 seconds.
  - Packet 3 arrives at 100.0 s. Flow 1 saw its last packet at 0.5 s. The gap is 99.5 s, so flow 1 leaves the table with `end_reason="idle_timeout"`.
  - Packet 5 arrives at 200.0 s. Flow 2 saw its last packet at 100.5 s. The gap is 99.5 s, so flow 2 leaves with `end_reason="idle_timeout"`.
  - Flow 1 is already gone when packet 5 arrives. Packet 5 therefore starts flow 3 and does not join flow 1.
  - Flow 3 stays in the table until the end of the input and has `end_reason="end_of_input"`.
- The flows file lists the flows in the order in which they left the table: flow 1, flow 2, flow 3.
- Flow 1 and flow 3 have the same endpoints `10.0.0.1:40000` and `10.0.0.2:53`. They have different `flow_id` values, because their start times differ (0.0 s and 200.0 s).
- Every flow has 2 packets: 1 forward, 1 backward. Every flow has `byte_count=169` (71 + 98), `duration=0.5`, and `application_protocol="DNS"`. The TCP fields are `null`.
- Each event carries the `flow_id` of its own flow. The directions alternate: `forward`, `backward`.

## Actual result

`output.jsonl` holds 6 events, `flows.jsonl` holds 3 flow records, and `console.txt` holds the console summary and the exit code 0. All events have `preprocess_status="valid"` and `processing_action="keep"`.

| Flow record | 1 | 2 | 3 |
|---|---|---|---|
| `flow_id` | `udp-499d79bf977b` | `udp-603b6a8f4761` | `udp-f9f270abe942` |
| `endpoint_a` | `10.0.0.1:40000` | `10.0.0.1:40001` | `10.0.0.1:40000` |
| `endpoint_b` | `10.0.0.2:53` | `10.0.0.2:53` | `10.0.0.2:53` |
| `start_time` (s after 1758441600) | 0.0 | 100.0 | 200.0 |
| `last_seen` (s after 1758441600) | 0.5 | 100.5 | 200.5 |
| `duration` | 0.5 | 0.5 | 0.5 |
| `packet_count`, `byte_count` | 2, 169 | 2, 169 | 2, 169 |
| forward `packet_count`, `byte_count` | 1, 71 | 1, 71 | 1, 71 |
| backward `packet_count`, `byte_count` | 1, 98 | 1, 98 | 1, 98 |
| `application_protocol` | `DNS` | `DNS` | `DNS` |
| `syn_count`, `ack_count`, `fin_count`, `rst_count`, `state` | `null` | `null` | `null` |
| `end_reason` | `idle_timeout` | `idle_timeout` | `end_of_input` |

Flow 1 has the same `flow_id` as the flow of `A2-T10_udp_flow`. The id depends only on the 5-tuple and the start time, and both cases have the same values for these.

Events 1 and 2 carry the id of flow 1, events 3 and 4 the id of flow 2, and events 5 and 6 the id of flow 3.

## Wireshark check

The owner opened `input.pcap` in Wireshark. The owner sent a screenshot of the packet list and the output of Statistics → Conversations → UDP.

**Packet list.**

| No. | Time | Source | Destination | Protocol | Length | Source Port | Destination Port | Info |
|---|---|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | DNS | 71 | 40000 | 53 | `Standard query 0x1234 A example.com` |
| 2 | 0.500000 | 10.0.0.2 | 10.0.0.1 | DNS | 98 | 53 | 40000 | `Standard query response 0x1234 A example.com A 93.184.216.34` |
| 3 | 100.000000 | 10.0.0.1 | 10.0.0.2 | DNS | 71 | 40001 | 53 | `Standard query 0x1234 A example.com` |
| 4 | 100.500000 | 10.0.0.2 | 10.0.0.1 | DNS | 98 | 53 | 40001 | `Standard query response 0x1234 A example.com A 93.184.216.34` |
| 5 | 200.000000 | 10.0.0.1 | 10.0.0.2 | DNS | 71 | 40000 | 53 | `Standard query 0x1234 A example.com` |
| 6 | 200.500000 | 10.0.0.2 | 10.0.0.1 | DNS | 98 | 53 | 40000 | `Standard query response 0x1234 A example.com A 93.184.216.34` |

**Statistics → Conversations → UDP.** Wireshark shows two conversations:

| Wireshark column | Conversation 1 | Conversation 2 |
|---|---|---|
| Address A, Port A | 10.0.0.1, 40000 | 10.0.0.1, 40001 |
| Address B, Port B | 10.0.0.2, 53 | 10.0.0.2, 53 |
| Packets | 4 | 2 |
| Packets A → B, Packets B → A | 2, 2 | 1, 1 |
| Bytes | 338 | 169 |
| Bytes A → B, Bytes B → A | 142, 196 | 71, 98 |
| Duration | 200.5 | 0.5 |
| Rel Start | 0 | 100 |

Conversation 1 holds the packets 1, 2, 5, and 6. Conversation 2 holds the packets 3 and 4.

**Comparison per packet.** The source, the destination, the ports, and the length of each Wireshark row equal those of the event with the same number. The time of each row equals the time of the event minus the time of event 1.

| Packet | Wireshark source:port → destination:port | Wireshark length | Wireshark time (s) | `direction` of the event | `flow_id` of the event | Match |
|---|---|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:53 | 71 | 0.0 | `forward` | `udp-499d79bf977b` | yes |
| 2 | 10.0.0.2:53 → 10.0.0.1:40000 | 98 | 0.5 | `backward` | `udp-499d79bf977b` | yes |
| 3 | 10.0.0.1:40001 → 10.0.0.2:53 | 71 | 100.0 | `forward` | `udp-603b6a8f4761` | yes |
| 4 | 10.0.0.2:53 → 10.0.0.1:40001 | 98 | 100.5 | `backward` | `udp-603b6a8f4761` | yes |
| 5 | 10.0.0.1:40000 → 10.0.0.2:53 | 71 | 200.0 | `forward` | `udp-f9f270abe942` | yes |
| 6 | 10.0.0.2:53 → 10.0.0.1:40000 | 98 | 200.5 | `backward` | `udp-f9f270abe942` | yes |

**Comparison per flow.**

| Item | Flow records | Wireshark | Match |
|---|---|---|---|
| Conversation of port 40001 against flow 2 | 2 packets, 169 bytes (71 forward, 98 backward), duration 0.5, start 100 s after flow 1 | 2 packets, 169 bytes (71, 98), duration 0.5, Rel Start 100 | yes |
| Conversation of port 40000 against flows 1 and 3 together | 4 packets (2 + 2), 338 bytes (169 + 169), 142 forward and 196 backward bytes, first packet at 0.0 s, last packet at 200.5 s | 4 packets, 338 bytes, 142 and 196 bytes, Duration 200.5 | yes |
| Number of flows | 3 | 2 conversations | see below |

Wireshark shows one conversation for the 5-tuple `10.0.0.1:40000 ↔ 10.0.0.2:53`, with a Duration of 200.5 s. The flow records split these 4 packets into flow 1 (packets 1 and 2) and flow 3 (packets 5 and 6). The packet times in the packet list give the reason: packet 5 comes 199.5 s after packet 2, and the idle timeout is 30 s. The gaps between the last packet of a flow and the next packet are 99.5 s (packet 2 to packet 3) and 99.5 s (packet 4 to packet 5). Both are more than 30 s. So the flow records agree with Wireshark in packets, bytes, and times, and the extra flow comes from the idle timeout.

## Verdict

PASS. Each of the 6 events has the source, destination, ports, length, and time that the Wireshark packet list gives. The packet and byte counts of the flow records add up to the Wireshark conversations. The two idle gaps are 99.5 s, longer than the 30 s timeout, so the tracker ends flow 1 and flow 2 before the end of the input and starts flow 3 for the reused 5-tuple.
