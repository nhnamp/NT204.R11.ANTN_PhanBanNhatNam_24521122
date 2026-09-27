# TC-03 — UDP

## Purpose

The parser must parse a UDP packet. The event must hold the UDP header fields and the payload.

## Input

`input.pcap` is a copy of `tests/fixtures/udp.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

| Packet | Direction | Payload |
|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:53 | `udp-payload!` (12 bytes) |

The destination port is 53, but the payload is not a DNS message. This is on purpose: the Application Protocol Detector (P5) must not trust the port alone.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-03_udp/input.pcap --output TEST/TC-03_udp/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `transport.protocol` is `"UDP"`, with ports 40000 and 53.
- `transport.length` is 20: the 8-byte UDP header plus 12 payload bytes.
- `transport.payload_len` and `payload_len` are 12, and `payload_preview` is the hex form of the payload.
- The event has `status="ok"` and no errors.
- `app_protocol` is `"UNKNOWN"` with `detection.method="none"`. The payload fails the DNS structure check, and the port hint applies only to an empty payload (R5.5), so port 53 alone does not make the packet DNS (`DET-1`).

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `network.proto_name` | `UDP` |
| `transport.protocol` | `UDP` |
| `transport.src_port`, `transport.dst_port` | 40000, 53 |
| `transport.length` | 20 |
| `transport.checksum` | 44139 (`0xac6b`) |
| `network.total_len` | 40 (20 IP + 8 UDP + 12 payload) |
| `transport.payload_len`, `payload_len` | 12, 12 |
| `payload_preview` | `7564702d7061796c6f616421` |
| `status`, `errors` | `ok`, `[]` |
| `app_protocol` | `UNKNOWN` |
| `detection` | `method="none"`, `confidence="low"`, `rule=""` |

The preview decodes to `udp-payload!`, the exact payload of the input. The TCP-only fields (`seq`, `ack`, `flags`, …) are `null` or empty.

Wireshark shows the same UDP header: ports 40000 and 53, length 20, and checksum `0xac6b`. With Decode As set to `(none)`, its 12-byte Data field equals the preview. By default, Wireshark labels the packet as a malformed DNS packet, because it selects the dissector by port 53.

## Retest after the detector (P5, R5.9)

The first run of this case had no Application Protocol Detector, so the event had `detection=null`. The retest changes only this field. `app_protocol` stays `"UNKNOWN"`. All network and transport fields are the same as in the first run.

The DNS rule rejects the payload at the header check. Bytes 2 and 3 of `udp-payload!` are `p-` (`0x702d`), so the opcode field (bits 11 to 14) is 14. The rule accepts only opcode 0 to 2. Wireshark shows the same value as "Unknown operation (14)", because it decodes the packet as DNS by port 53.

## Verdict

PASS.
