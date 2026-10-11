# A2-T13 — Flow statistics

## Purpose

The flow record must hold correct statistics: the packet count and the byte count for each direction, one counter for each TCP flag, and the duration (`FLOW-9`). The input has packets of different sizes, packets that carry data, and uneven times, so a wrong counter or a wrong duration shows up.

## Input

`input.pcap` is a copy of `tests/fixtures/flow_stats.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with the times of `FIXTURE_TIMES`. The times are uneven on purpose.

One TCP connection from `10.0.0.1:40000` to `10.0.0.2:4444`. No detector knows port 4444, so the flow has no application protocol.

| Packet | Time (s) | Direction | Flags | Frame length (bytes) | Payload (bytes) |
|---|---|---|---|---|---|
| 1 | 0.00 | 10.0.0.1:40000 → 10.0.0.2:4444 | SYN | 54 | 0 |
| 2 | 0.01 | 10.0.0.2:4444 → 10.0.0.1:40000 | SYN, ACK | 54 | 0 |
| 3 | 0.02 | 10.0.0.1:40000 → 10.0.0.2:4444 | ACK | 54 | 0 |
| 4 | 1.00 | 10.0.0.1:40000 → 10.0.0.2:4444 | PSH, ACK | 154 | 100 |
| 5 | 1.10 | 10.0.0.2:4444 → 10.0.0.1:40000 | ACK | 54 | 0 |
| 6 | 2.50 | 10.0.0.2:4444 → 10.0.0.1:40000 | PSH, ACK | 354 | 300 |
| 7 | 2.60 | 10.0.0.1:40000 → 10.0.0.2:4444 | ACK | 54 | 0 |
| 8 | 4.00 | 10.0.0.1:40000 → 10.0.0.2:4444 | FIN, ACK | 54 | 0 |
| 9 | 4.10 | 10.0.0.2:4444 → 10.0.0.1:40000 | FIN, ACK | 54 | 0 |
| 10 | 4.20 | 10.0.0.1:40000 → 10.0.0.2:4444 | ACK | 54 | 0 |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T13_flow_statistics/input.pcap --output TEST/A2-T13_flow_statistics/output.jsonl --flows-output TEST/A2-T13_flow_statistics/flows.jsonl
```

## Expected result

The fixture builder computes the expected values with the function `expected_flow_stats()` in `tests/fixtures/build_pcaps.py`. The function reads the packets and the times of the fixture. It does not call the flow tracker.

| Field of the flow record | Expected value | How it follows from the input |
|---|---|---|
| `packet_count` | 10 | The file has 10 packets. |
| `forward_packet_count`, `backward_packet_count` | 6, 4 | Packets 1, 3, 4, 7, 8, 10 come from endpoint A. Packets 2, 5, 6, 9 come from endpoint B. |
| `byte_count` | 940 | The sum of the frame lengths. |
| `forward_byte_count`, `backward_byte_count` | 424, 516 | Forward: 5 × 54 + 154. Backward: 3 × 54 + 354. |
| `syn_count` | 2 | Packets 1 and 2 carry SYN. |
| `ack_count` | 9 | Every packet except packet 1 carries ACK. |
| `fin_count` | 2 | Packets 8 and 9 carry FIN. |
| `rst_count` | 0 | No packet carries RST. |
| `duration` | 4.2 | The last packet is at 4.20 s and the first at 0.00 s. |

Other fields:
- The run writes 10 events and 1 flow record, and exits with code 0.
- All 10 events have the same `flow_id`. The directions follow the table in the Input section.
- `state="CLOSED"`: the FIN at packet 8 starts the close, the FIN at packet 9 comes from the other side, and the ACK at packet 10 comes from the side of the first FIN.
- `application_protocol="UNKNOWN"` and `end_reason="end_of_input"`.

Limit of this check: the same builder makes the file and the expected values. A mistake in a packet size in the builder would change both, and the comparison would still match. The Wireshark reading below is the check that does not depend on the builder.

## Actual result

`output.jsonl` holds 10 events, `flows.jsonl` holds 1 flow record, and `console.txt` holds the console summary and the exit code 0. All events have `preprocess_status="valid"` and `processing_action="keep"`.

| Field of the flow record | Value |
|---|---|
| `flow_id` | `tcp-a471b9d13f91` |
| `protocol`, `application_protocol` | `TCP`, `UNKNOWN` |
| `endpoint_a`, `endpoint_b` | `10.0.0.1:40000`, `10.0.0.2:4444` |
| `start_time`, `last_seen`, `duration` | 1758441600.0, 1758441604.2, 4.2 |
| `packet_count`, `byte_count` | 10, 940 |
| forward `packet_count`, `byte_count` | 6, 424 |
| backward `packet_count`, `byte_count` | 4, 516 |
| `syn_count`, `ack_count`, `fin_count`, `rst_count` | 2, 9, 2, 0 |
| `state` | `CLOSED` |
| `end_reason` | `end_of_input` |

The directions of the 10 events are: `forward`, `backward`, `forward`, `forward`, `backward`, `backward`, `forward`, `forward`, `backward`, `forward`.

## Wireshark check

The owner opened `input.pcap` in Wireshark. The owner sent a screenshot of the packet list, a screenshot of the filtered packet list for each of four display filters, and the output of Statistics → Conversations → TCP. The screenshots of the filtered lists do not show the status bar. The number of packets for a filter is the number of rows in its list.

**Packet list.**

| No. | Time | Source | Destination | Protocol | Length | Info |
|---|---|---|---|---|---|---|
| 1 | 0.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 4444 [SYN] Seq=0 Win=8192 Len=0` |
| 2 | 0.010000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `4444 → 40000 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0` |
| 3 | 0.020000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 4444 [ACK] Seq=1 Ack=1 Win=8192 Len=0` |
| 4 | 1.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 154 | `40000 → 4444 [PSH, ACK] Seq=1 Ack=1 Win=8192 Len=100` |
| 5 | 1.100000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `4444 → 40000 [ACK] Seq=1 Ack=101 Win=8192 Len=0` |
| 6 | 2.500000 | 10.0.0.2 | 10.0.0.1 | TCP | 354 | `4444 → 40000 [PSH, ACK] Seq=1 Ack=101 Win=8192 Len=300` |
| 7 | 2.600000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 4444 [ACK] Seq=101 Ack=301 Win=8192 Len=0` |
| 8 | 4.000000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 4444 [FIN, ACK] Seq=101 Ack=301 Win=8192 Len=0` |
| 9 | 4.100000 | 10.0.0.2 | 10.0.0.1 | TCP | 54 | `4444 → 40000 [FIN, ACK] Seq=301 Ack=102 Win=8192 Len=0` |
| 10 | 4.200000 | 10.0.0.1 | 10.0.0.2 | TCP | 54 | `40000 → 4444 [ACK] Seq=102 Ack=302 Win=8192 Len=0` |

**Statistics → Conversations → TCP.** Wireshark shows one conversation:

| Wireshark column | Value |
|---|---|
| Address A, Port A | 10.0.0.1, 40000 |
| Address B, Port B | 10.0.0.2, 4444 |
| Packets | 10 |
| Packets A → B, Packets B → A | 6, 4 |
| Bytes | 940 |
| Bytes A → B, Bytes B → A | 424, 516 |
| Duration | 4.2 |
| Rel Start | 0 |

**Flag counts.** Each row shows the packets that Wireshark lists for the filter.

| Display filter | Packets in the filtered list | Number of packets | Flow record counter | Value | Match |
|---|---|---|---|---|---|
| `tcp.flags.syn == 1` | 1, 2 | 2 | `syn_count` | 2 | yes |
| `tcp.flags.ack == 1` | 2, 3, 4, 5, 6, 7, 8, 9, 10 | 9 | `ack_count` | 9 | yes |
| `tcp.flags.fin == 1` | 8, 9 | 2 | `fin_count` | 2 | yes |
| `tcp.flags.reset == 1` | none (the list is empty) | 0 | `rst_count` | 0 | yes |

**Comparison per packet.** A packet from `10.0.0.1` is `forward`.

| Packet | Wireshark source → destination | Wireshark length | Wireshark flags | `direction` of the event | `length` of the event | `tcp_flags` of the event | Match |
|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.1 → 10.0.0.2 | 54 | SYN | `forward` | 54 | SYN | yes |
| 2 | 10.0.0.2 → 10.0.0.1 | 54 | SYN, ACK | `backward` | 54 | SYN, ACK | yes |
| 3 | 10.0.0.1 → 10.0.0.2 | 54 | ACK | `forward` | 54 | ACK | yes |
| 4 | 10.0.0.1 → 10.0.0.2 | 154 | PSH, ACK | `forward` | 154 | PSH, ACK | yes |
| 5 | 10.0.0.2 → 10.0.0.1 | 54 | ACK | `backward` | 54 | ACK | yes |
| 6 | 10.0.0.2 → 10.0.0.1 | 354 | PSH, ACK | `backward` | 354 | PSH, ACK | yes |
| 7 | 10.0.0.1 → 10.0.0.2 | 54 | ACK | `forward` | 54 | ACK | yes |
| 8 | 10.0.0.1 → 10.0.0.2 | 54 | FIN, ACK | `forward` | 54 | FIN, ACK | yes |
| 9 | 10.0.0.2 → 10.0.0.1 | 54 | FIN, ACK | `backward` | 54 | FIN, ACK | yes |
| 10 | 10.0.0.1 → 10.0.0.2 | 54 | ACK | `forward` | 54 | ACK | yes |

**Comparison per flow.**

| Item | Flow record | Wireshark | Match |
|---|---|---|---|
| Endpoints | `10.0.0.1:40000`, `10.0.0.2:4444` | 10.0.0.1:40000, 10.0.0.2:4444 | yes |
| `packet_count` | 10 | 10 | yes |
| Forward packets (`forward_packet_count`) | 6 | 6 | yes |
| Backward packets (`backward_packet_count`) | 4 | 4 | yes |
| `byte_count` | 940 | 940 | yes |
| Forward bytes (`forward_byte_count`) | 424 | 424 | yes |
| Backward bytes (`backward_byte_count`) | 516 | 516 | yes |
| `duration` | 4.2 | 4.2 | yes |

The Wireshark values equal both the flow record and the expected values of the Expected result section. This comparison does not depend on the fixture builder.

## Verdict

PASS. The packet count, the byte count for each direction, the four flag counters, and the duration of the flow record equal the Wireshark values. Each event has the `direction`, the length, and the flags that the Wireshark packet list gives.
