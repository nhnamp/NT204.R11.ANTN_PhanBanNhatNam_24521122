# A2-T08 — Bidirectional flow

## Purpose

The two directions of one TCP connection must belong to one flow (`FLOW-2`, `FLOW-4`). Every event must carry the id of its flow and the direction of its packet (`FLOW-3`). This case uses a connection with a payload in both directions: an HTTP request and its response.

## Input

`input.pcap` is a copy of `tests/fixtures/flow_http.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times.

| Packet | Time (s) | Packet goes from → to | Flags | Frame length (bytes) | Payload (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 54 | 0 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 54 | 0 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 | 0 |
| 4 | 1.5 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 101 | 47 (`GET /index.html`) |
| 5 | 2.0 | 10.0.0.2:80 → 10.0.0.1:40000 | ACK | 54 | 0 |
| 6 | 2.5 | 10.0.0.2:80 → 10.0.0.1:40000 | PSH, ACK | 97 | 43 (`HTTP/1.1 200 OK`) |
| 7 | 3.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 | 0 |

Every packet uses the same two endpoints. The source and the destination swap between the two directions.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T08_bidirectional_flow/input.pcap --output TEST/A2-T08_bidirectional_flow/output.jsonl --flows-output TEST/A2-T08_bidirectional_flow/flows.jsonl
```

## Expected result

- The run writes 7 events and 1 flow record, and exits with code 0.
- All 7 events have the same `flow_id`.
- The first packet is a SYN from `10.0.0.1:40000`, so this endpoint is endpoint A. A packet from endpoint A is `forward`. A packet from the other endpoint is `backward`.
- The directions are: `forward`, `backward`, `forward`, `forward`, `backward`, `backward`, `forward`. They follow the table in the Input section.
- The flow has `packet_count=7`, with 4 forward packets and 3 backward packets. `byte_count` is 468: forward 263 bytes (54 + 54 + 101 + 54) and backward 205 bytes (54 + 54 + 97).
- `state="ESTABLISHED"`. No packet has FIN or RST. `syn_count=2`, `ack_count=6`, `fin_count=0`, `rst_count=0`.
- `application_protocol="HTTP"` (the payload of packet 4 is an HTTP request), `duration=3.0`, and `end_reason="end_of_input"`.
- The flow id depends only on the 5-tuple and the start time. This case has the same 5-tuple and the same start time as `A2-T07_tcp_handshake`, so it has the same `flow_id`. The id is not a counter.

## Actual result

`output.jsonl` holds 7 events, `flows.jsonl` holds 1 flow record, and `console.txt` holds the console summary and the exit code 0.

All 7 events have `flow_id="tcp-5f8ec36d79cc"`, `preprocess_status="valid"`, and `processing_action="keep"`.

| Packet | `direction` |
|---|---|
| 1 | `forward` |
| 2 | `backward` |
| 3 | `forward` |
| 4 | `forward` |
| 5 | `backward` |
| 6 | `backward` |
| 7 | `forward` |

| Field of the flow record | Value |
|---|---|
| `flow_id` | `tcp-5f8ec36d79cc` |
| `protocol`, `application_protocol` | `TCP`, `HTTP` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:80` |
| `start_time`, `last_seen`, `duration` | 1758441600.0, 1758441603.0, 3.0 |
| `packet_count`, `byte_count` | 7, 468 |
| forward `packet_count`, `byte_count` | 4, 263 |
| backward `packet_count`, `byte_count` | 3, 205 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count` | 2, 6, 0, 0 |
| `state` | `ESTABLISHED` |
| `end_reason` | `end_of_input` |

## Wireshark check

The owner opened `input.pcap` in Wireshark.

**Packet list.** The owner sent a screenshot of the 7 rows of the packet list:

| No. | Time | Source | Destination | Protocol | Length | Info |
|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 2 | 0.500000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 3 | 1.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 4 | 1.500000 | 10.0.0.1 | 10.0.0.2 | HTTP | 101 | `GET /index.html HTTP/1.1` |
| 5 | 2.000000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [ACK] Seq=1 Ack=48 Win=8192 Len=0` |
| 6 | 2.500000 | 10.0.0.2 | 10.0.0.1 | HTTP | 97 | `HTTP/1.1 200 OK` |
| 7 | 3.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [ACK] Seq=48 Ack=44 Win=8192 Len=0` |

Wireshark does not show the flags of packets 4 and 6 in the Info column, because its HTTP view replaces them. The owner wrote the flags of all packets as one line in an earlier reading: `SYN - SYN, ACK - ACK - PSH, ACK - ACK, PSH, ACK - ACK`.

**Statistics → Conversations → TCP.** Wireshark shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 80 |
| Packets | 7 |
| Packets A → B, Packets B → A | 4, 3 |
| Bytes | 468 |
| Bytes A → B, Bytes B → A | 263, 205 |
| Duration | 3 |

**Follow TCP Stream.** One stream holds both messages. The owner copied this text:

```
GET /index.html HTTP/1.1
Host: example.com


HTTP/1.1 200 OK
Content-Length: 5

hello
```

The owner did not record the byte count of each direction in this view.

The comparison with the flow record, per packet. The flow record names endpoint A `10.0.0.1:40000`. A packet from `10.0.0.1` is `forward`.

| Packet | Wireshark source → destination | Wireshark length | `direction` of the event | `length` of the event | Match |
|---|---|---|---|---|---|
| 1 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 2 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 3 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 4 | 10.0.0.1 → 10.0.0.2 | 101 | `forward` | 101 | yes |
| 5 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 6 | 10.0.0.2 → 10.0.0.1 | 97 | `backward` | 97 | yes |
| 7 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |

The comparison with the flow record, per flow:

| Item | Flow record | Wireshark |
|---|---|---|
| Number of flows | 1 | 1 conversation |
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:80` | 10.0.0.1:40000, 10.0.0.2:80 |
| `packet_count` | 7 | 7 |
| Forward / backward packets | 4 / 3 | 4 / 3 |
| `byte_count` | 468 | 468 |
| Forward / backward bytes | 263 / 205 | 263 / 205 |
| `duration` | 3.0 | 3 |
| Packets that share one flow | all 7 events, one `flow_id` | one conversation, one stream |
| Application data | `application_protocol="HTTP"` | the stream shows a GET request and a `200 OK` response |

## Verdict

PASS. Each of the 7 events has the `direction` that the Wireshark source and destination give, and the same length. The flow record matches the Wireshark conversation in endpoints, packet counts, byte counts for each direction, and duration. Follow TCP Stream shows the request and the response in one stream.
