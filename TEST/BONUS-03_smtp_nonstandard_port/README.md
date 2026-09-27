# BONUS-03 — SMTP on a non-standard port

## Purpose

The detector must recognise SMTP on a port other than 25 (`DET-4`). Both the client commands and the server responses must be detected from the payload alone.

## Input

`input.pcap` is a copy of `tests/fixtures/bonus_smtp_2526.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times.

The file holds the same 13-packet SMTP session as TC-09 and TC-10, on port 2526 instead of 25. The client is 10.0.0.1:40000, and the server is 10.0.0.2:2526.

Port 2526 is not in the hint table (R5.4). Port 2525 is a common alternate SMTP port and is in the table, so this case uses 2526 to prove detection without a hint.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/BONUS-03_smtp_nonstandard_port/input.pcap --output TEST/BONUS-03_smtp_nonstandard_port/output.jsonl
```

## Expected result

- The run writes 13 events and exits with code 0. Every event has `status="ok"` and no errors.
- The 12 command and response packets have `app_protocol="SMTP"`, `detection.method="payload"`, and `detection.confidence="high"`.
- `detection.rule` is `smtp_command` for the client packets and `smtp_response` for the server packets.
- Packet 10 carries only message content, so it has `app_protocol="UNKNOWN"` and `detection.method="none"`, the same as in TC-09 (R8.2).
- The SMTP parser fills `application` the same way as on port 25.

## Actual result

`output.jsonl` holds 13 events. `console.txt` holds the console summary and the exit code 0.

| `packet_id` | Direction | `app_protocol` | `detection.method` | `detection.rule` | Parsed lines |
|---|---|---|---|---|---|
| 1 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 220 |
| 2 | 40000 → 2526 | `SMTP` | `payload` | `smtp_command` | `EHLO` |
| 3 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 250, 250, 250, 250 |
| 4 | 40000 → 2526 | `SMTP` | `payload` | `smtp_command` | `MAIL FROM` |
| 5 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 250 |
| 6 | 40000 → 2526 | `SMTP` | `payload` | `smtp_command` | `RCPT TO` |
| 7 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 250 |
| 8 | 40000 → 2526 | `SMTP` | `payload` | `smtp_command` | `DATA` |
| 9 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 354 |
| 10 | 40000 → 2526 | `UNKNOWN` | `none` | — | `application=null` |
| 11 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 250 |
| 12 | 40000 → 2526 | `SMTP` | `payload` | `smtp_command` | `QUIT` |
| 13 | 2526 → 40000 | `SMTP` | `payload` | `smtp_response` | 221 |

All 13 events have `status="ok"` and no errors.

Apart from the ports, the checksums, and `detection`, the events are the same as in TC-09. So the port changes only how the protocol is decided, not what the parser reads.

The response rule is stricter without a hint. On port 25 a reply code alone is enough, because the hint names SMTP. On port 2526 the rule also requires printable ASCII text that ends with CRLF (R5.3). Every server response in this session passes that check.

Wireshark shows the 13 packets on port 2526 only as TCP, because 2526 is not in its list of SMTP ports. The parser recognises SMTP on 12 of them from the payload alone.

## Verdict

PASS.
