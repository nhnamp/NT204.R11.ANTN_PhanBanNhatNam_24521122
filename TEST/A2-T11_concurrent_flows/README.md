# A2-T11 — Concurrent flows

## Purpose

The flow tracker must keep several connections apart when their packets alternate in one file (`FLOW-2`, `FLOW-3`). Each flow must have its own `flow_id`. No packet may join the wrong flow. This case has two TCP flows with the same hosts and the same server port, a third TCP flow to another server, and one UDP flow.

## Input

`input.pcap` is a copy of `tests/fixtures/concurrent_flows.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times. The flow number in the table is the order of the first packet of each flow. It is a label of this README, not a field of the output.

| Packet | Time (s) | Flow | Packet goes from → to | Protocol | Flags | Frame length (bytes) | Payload (bytes) |
|---|---|---|---|---|---|---|---|
| 1 | 0.0 | 1 | 10.0.0.1:40000 → 10.0.0.2:80 | TCP | SYN | 54 | 0 |
| 2 | 0.5 | 2 | 10.0.0.1:40001 → 10.0.0.2:80 | TCP | SYN | 54 | 0 |
| 3 | 1.0 | 1 | 10.0.0.2:80 → 10.0.0.1:40000 | TCP | SYN, ACK | 54 | 0 |
| 4 | 1.5 | 3 | 10.0.0.1:40002 → 10.0.0.3:80 | TCP | SYN | 54 | 0 |
| 5 | 2.0 | 2 | 10.0.0.2:80 → 10.0.0.1:40001 | TCP | SYN, ACK | 54 | 0 |
| 6 | 2.5 | 1 | 10.0.0.1:40000 → 10.0.0.2:80 | TCP | ACK | 54 | 0 |
| 7 | 3.0 | 4 | 10.0.0.1:40003 → 10.0.0.2:53 | UDP | — | 71 | 29 |
| 8 | 3.5 | 3 | 10.0.0.3:80 → 10.0.0.1:40002 | TCP | SYN, ACK | 54 | 0 |
| 9 | 4.0 | 2 | 10.0.0.1:40001 → 10.0.0.2:80 | TCP | ACK | 54 | 0 |
| 10 | 4.5 | 4 | 10.0.0.2:53 → 10.0.0.1:40003 | UDP | — | 98 | 56 |
| 11 | 5.0 | 3 | 10.0.0.1:40002 → 10.0.0.3:80 | TCP | ACK | 54 | 0 |
| 12 | 5.5 | 1 | 10.0.0.1:40000 → 10.0.0.2:80 | TCP | PSH, ACK | 101 | 47 |

Flows 1 and 2 use the same two hosts and the same server port. Only the client port differs (40000 and 40001). Flow 3 uses another server. Flow 4 uses UDP.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T11_concurrent_flows/input.pcap --output TEST/A2-T11_concurrent_flows/output.jsonl --flows-output TEST/A2-T11_concurrent_flows/flows.jsonl
```

## Expected result

- The run writes 12 events and 4 flow records, and exits with code 0.
- The 4 flows have 4 different `flow_id` values.
- The packet counts are: flow 1 has 4 packets, flow 2 has 3, flow 3 has 3, and flow 4 has 2. The total is 12.
- Each event has the `flow_id` of the flow that holds its endpoint pair. The packets of one flow never share the `flow_id` of another flow.
- Flows 1 to 3 are TCP flows in the state `ESTABLISHED`, with `syn_count=2`. `ack_count` is 3 for flow 1 (its data packet carries ACK) and 2 for flows 2 and 3. Flow 4 is a UDP flow: its TCP counters and `state` are `null`.
- All flows have `end_reason="end_of_input"`. The flows file lists the flows in order of `start_time`.
- Flow 1 has the same 5-tuple and the same start time as the flows of `A2-T07_tcp_handshake` and `A2-T08_bidirectional_flow`, so it has the same `flow_id`. The id depends only on the 5-tuple and the start time.
- `application_protocol` is `HTTP` for the three TCP flows and `DNS` for the UDP flow. Flow 1 has an HTTP request in packet 12. Flows 2 and 3 have no payload, so the port decides (port 80). The UDP packets hold DNS messages.

## Actual result

`output.jsonl` holds 12 events, `flows.jsonl` holds 4 flow records, and `console.txt` holds the console summary and the exit code 0. All events have `preprocess_status="valid"` and `processing_action="keep"`.

Flow and direction of each event:

| Packet | Flow | `flow_id` | `direction` |
|---|---|---|---|
| 1 | 1 | `tcp-5f8ec36d79cc` | `forward` |
| 2 | 2 | `tcp-ad50c357ecc8` | `forward` |
| 3 | 1 | `tcp-5f8ec36d79cc` | `backward` |
| 4 | 3 | `tcp-6017283c3246` | `forward` |
| 5 | 2 | `tcp-ad50c357ecc8` | `backward` |
| 6 | 1 | `tcp-5f8ec36d79cc` | `forward` |
| 7 | 4 | `udp-d3fddae37943` | `forward` |
| 8 | 3 | `tcp-6017283c3246` | `backward` |
| 9 | 2 | `tcp-ad50c357ecc8` | `forward` |
| 10 | 4 | `udp-d3fddae37943` | `backward` |
| 11 | 3 | `tcp-6017283c3246` | `forward` |
| 12 | 1 | `tcp-5f8ec36d79cc` | `forward` |

The flow records:

| Field | Flow 1 | Flow 2 | Flow 3 | Flow 4 |
|---|---|---|---|---|
| `flow_id` | `tcp-5f8ec36d79cc` | `tcp-ad50c357ecc8` | `tcp-6017283c3246` | `udp-d3fddae37943` |
| `protocol`, `application_protocol` | `TCP`, `HTTP` | `TCP`, `HTTP` | `TCP`, `HTTP` | `UDP`, `DNS` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:80` | `10.0.0.1:40001`, `10.0.0.2:80` | `10.0.0.1:40002`, `10.0.0.3:80` | `10.0.0.1:40003`, `10.0.0.2:53` |
| `start_time` offset, `duration` | 0.0, 5.5 | 0.5, 3.5 | 1.5, 3.5 | 3.0, 1.5 |
| `packet_count`, `byte_count` | 4, 263 | 3, 162 | 3, 162 | 2, 169 |
| forward `packet_count`, `byte_count` | 3, 209 | 2, 108 | 2, 108 | 1, 71 |
| backward `packet_count`, `byte_count` | 1, 54 | 1, 54 | 1, 54 | 1, 98 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count` | 2, 3, 0, 0 | 2, 2, 0, 0 | 2, 2, 0, 0 | `null` |
| `state` | `ESTABLISHED` | `ESTABLISHED` | `ESTABLISHED` | `null` |
| `end_reason` | `end_of_input` | `end_of_input` | `end_of_input` | `end_of_input` |

## Wireshark check

The owner opened `input.pcap` in Wireshark and added the source port and the destination port as columns. The owner sent a screenshot of the packet list and the output of Statistics → Conversations for the TCP tab and for the UDP tab.

**Packet list.** Wireshark shows two pairs of port columns: one pair for TCP and one pair for UDP. A TCP row fills the first pair. A UDP row fills the second pair. The table shows the filled pair as one pair of columns.

| No. | Time | Source | Destination | Protocol | Length | Source Port | Destination Port | Info |
|---|---|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | 40000 | 80 | `40000 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 2 | 0.500000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | 40001 | 80 | `40001 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 3 | 1.000000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | 80 | 40000 | `80 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 4 | 1.500000 | 10.0.0.1 | 10.0.0.3 | TCP | 54 | 40002 | 80 | `40002 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 5 | 2.000000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | 80 | 40001 | `80 → 40001 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 6 | 2.500000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | 40000 | 80 | `40000 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 7 | 3.000000 | 10.0.0.1 | 10.0.0.2 | DNS | 71 | 40003 | 53 | `Standard query 0x1234 A example.com` |
| 8 | 3.500000 | 10.0.0.3 | 10.0.0.1 | TCP | 54 | 80 | 40002 | `80 → 40002 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 9 | 4.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | 40001 | 80 | `40001 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 10 | 4.500000 | 10.0.0.2 | 10.0.0.1 | DNS | 98 | 53 | 40003 | `Standard query response 0x1234 A example.com A 93.184.216.34` |
| 11 | 5.000000 | 10.0.0.1 | 10.0.0.3 | TCP | 54 | 40002 | 80 | `40002 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 12 | 5.500000 | 10.0.0.1 | 10.0.0.2 | HTTP | 101 | 40000 | 80 | `GET /index.html HTTP/1.1` |

**Statistics → Conversations.** The TCP tab shows 3 conversations and the UDP tab shows 1 conversation. The flow number is the label of this README: it is the order of the first packet.

| Flow | Tab | Address A:Port A | Address B:Port B | Packets | Packets A → B | Packets B → A | Bytes | Bytes A → B | Bytes B → A | Duration | Rel Start |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | TCP | 10.0.0.1:40000 | 10.0.0.2:80 | 4 | 3 | 1 | 263 | 209 | 54 | 5.5 | 0 |
| 2 | TCP | 10.0.0.1:40001 | 10.0.0.2:80 | 3 | 2 | 1 | 162 | 108 | 54 | 3.5 | 0.5 |
| 3 | TCP | 10.0.0.1:40002 | 10.0.0.3:80 | 3 | 2 | 1 | 162 | 108 | 54 | 3.5 | 1.5 |
| 4 | UDP | 10.0.0.1:40003 | 10.0.0.2:53 | 2 | 1 | 1 | 169 | 71 | 98 | 1.5 | 3 |

**Comparison per packet.** The table keys each packet on its full endpoint pair. The pair of a packet must be the pair of the two endpoints of the flow that its event names. A packet from endpoint A of the flow is `forward`.

| Packet | Wireshark endpoint pair | Wireshark length | Flow of the event | `direction` of the event | Pair is one of the two endpoints of that flow | `length` equal |
|---|---|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | 54 | 1 | `forward` | yes | yes |
| 2 | 10.0.0.1:40001 → 10.0.0.2:80 | 54 | 2 | `forward` | yes | yes |
| 3 | 10.0.0.2:80 → 10.0.0.1:40000 | 54 | 1 | `backward` | yes | yes |
| 4 | 10.0.0.1:40002 → 10.0.0.3:80 | 54 | 3 | `forward` | yes | yes |
| 5 | 10.0.0.2:80 → 10.0.0.1:40001 | 54 | 2 | `backward` | yes | yes |
| 6 | 10.0.0.1:40000 → 10.0.0.2:80 | 54 | 1 | `forward` | yes | yes |
| 7 | 10.0.0.1:40003 → 10.0.0.2:53 | 71 | 4 | `forward` | yes | yes |
| 8 | 10.0.0.3:80 → 10.0.0.1:40002 | 54 | 3 | `backward` | yes | yes |
| 9 | 10.0.0.1:40001 → 10.0.0.2:80 | 54 | 2 | `forward` | yes | yes |
| 10 | 10.0.0.2:53 → 10.0.0.1:40003 | 98 | 4 | `backward` | yes | yes |
| 11 | 10.0.0.1:40002 → 10.0.0.3:80 | 54 | 3 | `forward` | yes | yes |
| 12 | 10.0.0.1:40000 → 10.0.0.2:80 | 101 | 1 | `forward` | yes | yes |

**Comparison per flow.** Each cell shows the flow record, then the Wireshark value.

| Flow | `packet_count` | Forward packets | Backward packets | `byte_count` | Forward bytes | Backward bytes | `duration` | `start_time` offset | Match |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 4 / 4 | 3 / 3 | 1 / 1 | 263 / 263 | 209 / 209 | 54 / 54 | 5.5 / 5.5 | 0 / 0 | yes |
| 2 | 3 / 3 | 2 / 2 | 1 / 1 | 162 / 162 | 108 / 108 | 54 / 54 | 3.5 / 3.5 | 0.5 / 0.5 | yes |
| 3 | 3 / 3 | 2 / 2 | 1 / 1 | 162 / 162 | 108 / 108 | 54 / 54 | 3.5 / 3.5 | 1.5 / 1.5 | yes |
| 4 | 2 / 2 | 1 / 1 | 1 / 1 | 169 / 169 | 71 / 71 | 98 / 98 | 1.5 / 1.5 | 3 / 3 | yes |

The 4 flow records have 4 different `flow_id` values: `tcp-5f8ec36d79cc`, `tcp-ad50c357ecc8`, `tcp-6017283c3246`, and `udp-d3fddae37943`. Wireshark shows 4 conversations: 3 TCP and 1 UDP. Wireshark does not show the logical state.

## Verdict

PASS. Wireshark shows 3 TCP conversations and 1 UDP conversation, and the tracker has 4 flows. Each of the 12 events names the flow that holds its endpoint pair, with the `direction` and the length that the Wireshark packet list gives. Each flow record matches its conversation in endpoints, packet counts, byte counts for each direction, duration, and start time. No packet is in the wrong flow.
