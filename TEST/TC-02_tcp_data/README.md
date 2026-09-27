# TC-02 — TCP data

## Purpose

The parser must parse a TCP packet that carries a payload. The event must hold the payload length and a preview of the payload bytes.

## Input

`input.pcap` is a copy of `tests/fixtures/tcp_data.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

| Packet | Direction | Flags | Seq | Ack | Payload |
|---|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 1001 | 5001 | `0123456789abcdefghij` (20 bytes) |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-02_tcp_data/input.pcap --output TEST/TC-02_tcp_data/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `transport.payload_len` and `payload_len` are 20.
- `payload_preview` is the hex form of the 20 payload bytes.
- `transport.handshake` is `null`, because the packet carries data.
- The event has `status="ok"` and no errors.
- `app_protocol` is `"UNKNOWN"` with `detection.method="none"`. The payload matches no payload rule, and the port hint applies only to an empty payload (R5.5), so port 80 alone does not make the packet HTTP (`DET-1`).

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `transport.flags` | `["PSH", "ACK"]` |
| `transport.seq`, `transport.ack` | 1001, 5001 |
| `transport.data_offset` | 5 (20-byte TCP header) |
| `network.total_len` | 60 (20 IP + 20 TCP + 20 payload) |
| `transport.payload_len`, `payload_len` | 20, 20 |
| `payload_preview` | `303132333435363738396162636465666768696a` |
| `transport.handshake` | `null` |
| `status`, `errors` | `ok`, `[]` |
| `app_protocol` | `UNKNOWN` |
| `detection` | `method="none"`, `confidence="low"`, `rule=""` |

The preview decodes to `0123456789abcdefghij`, the exact payload of the input.

Wireshark shows the same packet: `[PSH, ACK]` with `Len=20`, and a 20-byte Data field equal to the preview. Its raw sequence number, acknowledgment number, and header length match the table.

## Retest after the detector (P5, R5.9)

The first run of this case had no Application Protocol Detector, so the event had `detection=null`. The retest changes only this field. `app_protocol` stays `"UNKNOWN"`, because the payload `0123456789abcdefghij` is not an HTTP message, even on port 80. All network and transport fields are the same as in the first run.

## Verdict

PASS.
