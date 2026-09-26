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

## Actual result

`output.jsonl` holds 3 events. `console.txt` holds the console summary and the exit code 0.

| `packet_id` | `transport.flags` | `transport.flags_str` | `seq` | `ack` | `transport.handshake` | `status` |
|---|---|---|---|---|---|---|
| 1 | `["SYN"]` | `S` | 1000 | 0 | `SYN` | `ok` |
| 2 | `["SYN", "ACK"]` | `SA` | 5000 | 1001 | `SYN/ACK` | `ok` |
| 3 | `["ACK"]` | `A` | 1001 | 5001 | `ACK` | `ok` |

The events hold absolute sequence numbers. Wireshark shows relative numbers by default, so packet 1 shows `Seq=0` there.

Wireshark shows the same three steps: `[SYN]`, `[SYN, ACK]`, and `[ACK]`. Its raw sequence and acknowledgment numbers match the table.

## Verdict

PASS.
