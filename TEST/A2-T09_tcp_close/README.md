# A2-T09 — TCP close

## Purpose

A TCP connection ends in one of two ways. A close, where each side sends a FIN, moves the flow to `CLOSED`. A reset, where one side sends a RST, moves the flow to `RESET` (`FLOW-5`, `FLOW-6`). Each way has its own input file.

## Input

`input/` holds two files. The script `tests/fixtures/build_pcaps.py` generates them with fixed times. Each file is a copy of the fixture with the same name in `tests/fixtures/`.

`tcp_close_fin.pcap` (7 packets):

| Packet | Time (s) | Direction | Flags | Frame length (bytes) |
|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 54 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 54 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 |
| 4 | 1.5 | 10.0.0.1:40000 → 10.0.0.2:80 | FIN, ACK | 54 |
| 5 | 2.0 | 10.0.0.2:80 → 10.0.0.1:40000 | ACK | 54 |
| 6 | 2.5 | 10.0.0.2:80 → 10.0.0.1:40000 | FIN, ACK | 54 |
| 7 | 3.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 |

`tcp_close_rst.pcap` (5 packets):

| Packet | Time (s) | Direction | Flags | Frame length (bytes) | Payload (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 54 | 0 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 54 | 0 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 54 | 0 |
| 4 | 1.5 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 101 | 47 (`GET /index.html`) |
| 5 | 2.0 | 10.0.0.2:80 → 10.0.0.1:40000 | RST, ACK | 54 | 0 |

## Commands

Run the commands from the repository root. One run per input file.

```bash
for f in TEST/A2-T09_tcp_close/input/*; do n=$(basename "$f" .pcap); python main.py --pcap "$f" --output "TEST/A2-T09_tcp_close/output/$n.jsonl" --flows-output "TEST/A2-T09_tcp_close/flows/$n.jsonl"; done
```

## Expected result

- Both runs write one flow record and exit with code 0.
- Both flows have the same `flow_id`, `tcp-5f8ec36d79cc`. The id depends only on the 5-tuple and the start time, and both files have the same 5-tuple and the same start time. The same id is in `A2-T07_tcp_handshake` and `A2-T08_bidirectional_flow`.
- `tcp_close_fin.pcap`: `state="CLOSED"`, `fin_count=2`, `rst_count=0`. The state becomes `CLOSING` at packet 4 (the first FIN). Packet 6 is the later FIN. Packet 7 is the ACK from the other side, so the state becomes `CLOSED`. `packet_count=7`, `byte_count=378`, forward 4 packets and 216 bytes, backward 3 packets and 162 bytes, `syn_count=2`, `ack_count=6`, `duration=3.0`.
- `tcp_close_rst.pcap`: `state="RESET"`, `rst_count=1`, `fin_count=0`. The RST at packet 5 moves the state from `ESTABLISHED` to `RESET`. `packet_count=5`, `byte_count=317`, forward 3 packets and 209 bytes, backward 2 packets and 108 bytes, `syn_count=2`, `ack_count=4`, `duration=2.0`.
- Both flows have `end_reason="end_of_input"`, because the input ends before the idle timeout.
- A flow is `CLOSED` only after the ACK of the later FIN. A capture that has both FINs and no last ACK stays `CLOSING`. The reason: two FINs alone do not prove that the last FIN arrived.

## Actual result

`output/` holds the events of each run, `flows/` holds the flow record of each run, and `console.txt` holds both commands, their summaries, and their exit codes. Both exit codes are 0. All events have `preprocess_status="valid"` and `processing_action="keep"`.

| Field of the flow record | `tcp_close_fin` | `tcp_close_rst` |
|---|---|---|
| `flow_id` | `tcp-5f8ec36d79cc` | `tcp-5f8ec36d79cc` |
| `protocol`, `application_protocol` | `TCP`, `HTTP` | `TCP`, `HTTP` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:80` | `10.0.0.1:40000`, `10.0.0.2:80` |
| `start_time`, `last_seen`, `duration` | 1758441600.0, 1758441603.0, 3.0 | 1758441600.0, 1758441602.0, 2.0 |
| `packet_count`, `byte_count` | 7, 378 | 5, 317 |
| forward `packet_count`, `byte_count` | 4, 216 | 3, 209 |
| backward `packet_count`, `byte_count` | 3, 162 | 2, 108 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count` | 2, 6, 2, 0 | 2, 4, 0, 1 |
| `state` | `CLOSED` | `RESET` |
| `end_reason` | `end_of_input` | `end_of_input` |

`application_protocol` is `HTTP` for both flows. In `tcp_close_fin` no packet has a payload, so the port decides (port 80). In `tcp_close_rst` the payload of packet 4 is an HTTP request.

The `direction` of the events in `tcp_close_fin` is: `forward`, `backward`, `forward`, `forward`, `backward`, `backward`, `forward`. The `direction` of the events in `tcp_close_rst` is: `forward`, `backward`, `forward`, `forward`, `backward`.

## Wireshark check

The owner opened each input file in Wireshark. The owner sent a screenshot of the packet list and the output of Statistics → Conversations → TCP for each file.

### `tcp_close_fin.pcap`

Packet list:

| No. | Time | Source | Destination | Protocol | Length | Info |
|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 2 | 0.500000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 3 | 1.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 4 | 1.500000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [FIN, ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 5 | 2.000000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [ACK] Seq=1 Ack=2 Win=8192 Len=0` |
| 6 | 2.500000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [FIN, ACK] Seq=1 Ack=2 Win=8192 Len=0` |
| 7 | 3.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [ACK] Seq=2 Ack=2 Win=8192 Len=0` |

Statistics → Conversations → TCP shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 80 |
| Packets | 7 |
| Packets A → B, Packets B → A | 4, 3 |
| Bytes | 378 |
| Bytes A → B, Bytes B → A | 216, 162 |
| Duration | 3 |

Comparison per packet. The flow record names endpoint A `10.0.0.1:40000`. A packet from `10.0.0.1` is `forward`.

| Packet | Wireshark source → destination | Wireshark length | `direction` of the event | `length` of the event | Match |
|---|---|---|---|---|---|
| 1 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 2 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 3 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 4 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 5 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 6 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 7 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |

Comparison per flow:

| Item | Flow record | Wireshark |
|---|---|---|
| Number of flows | 1 | 1 conversation |
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:80` | 10.0.0.1:40000, 10.0.0.2:80 |
| `packet_count` | 7 | 7 |
| Forward / backward packets | 4 / 3 | 4 / 3 |
| `byte_count` | 378 | 378 |
| Forward / backward bytes | 216 / 162 | 216 / 162 |
| `duration` | 3.0 | 3 |
| FIN packets | `fin_count=2` (packets 4 and 6) | `[FIN, ACK]` at packets 4 and 6 |

Wireshark does not show the logical state. The packet list follows the rule for `CLOSED`: the FIN at packet 4 starts the close, the FIN at packet 6 comes from the other side, and the ACK at packet 7 comes from the side that sent the first FIN, after the later FIN.

### `tcp_close_rst.pcap`

Packet list:

| No. | Time | Source | Destination | Protocol | Length | Info |
|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [SYN] Seq=0 Win=8192 Len=0` |
| 2 | 0.500000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 3 | 1.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 80 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 4 | 1.500000 | 10.0.0.1 | 10.0.0.2 | HTTP | 101 | `GET /index.html HTTP/1.1` |
| 5 | 2.000000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `80 → 40000 [RST, ACK] Seq=1 Ack=48 Win=8192 Len=0` |

Statistics → Conversations → TCP shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 80 |
| Packets | 5 |
| Packets A → B, Packets B → A | 3, 2 |
| Bytes | 317 |
| Bytes A → B, Bytes B → A | 209, 108 |
| Duration | 2 |

Wireshark does not show the flags of packet 4 in the Info column, because its HTTP view replaces them.

Comparison per packet:

| Packet | Wireshark source → destination | Wireshark length | `direction` of the event | `length` of the event | Match |
|---|---|---|---|---|---|
| 1 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 2 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |
| 3 | 10.0.0.1 → 10.0.0.2 | 54 | `forward` | 54 | yes |
| 4 | 10.0.0.1 → 10.0.0.2 | 101 | `forward` | 101 | yes |
| 5 | 10.0.0.2 → 10.0.0.1 | 54 | `backward` | 54 | yes |

Comparison per flow:

| Item | Flow record | Wireshark |
|---|---|---|
| Number of flows | 1 | 1 conversation |
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:80` | 10.0.0.1:40000, 10.0.0.2:80 |
| `packet_count` | 5 | 5 |
| Forward / backward packets | 3 / 2 | 3 / 2 |
| `byte_count` | 317 | 317 |
| Forward / backward bytes | 209 / 108 | 209 / 108 |
| `duration` | 2.0 | 2 |
| RST packets | `rst_count=1` (packet 5) | `[RST, ACK]` at packet 5 |

Wireshark does not show the logical state. The packet list follows the rule for `RESET`: the RST at packet 5 comes after the established connection.

## Verdict

PASS. For both files, each event has the `direction` and the length that the Wireshark packet list gives. Each flow record matches the Wireshark conversation in endpoints, packet counts, byte counts for each direction, and duration. The packet list shows the FIN close in one file and the RST in the other, and the flow records end in `CLOSED` and `RESET` as the rules say.
