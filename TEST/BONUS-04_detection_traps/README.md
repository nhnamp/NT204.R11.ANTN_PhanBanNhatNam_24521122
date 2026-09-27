# BONUS-04 — Detection traps

## Purpose

The detector must not trust a well-known port alone (`DET-1`). Random bytes on port 80, 53, or 25 must stay `UNKNOWN`. A real HTTP request on port 53 must be HTTP, although the port suggests DNS. This case is the reverse side of BONUS-01 to BONUS-03.

## Input

`input.pcap` is a copy of `tests/fixtures/bonus_traps.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times and the random seed 13.

| Packet | Transport and port | Port hint (R5.4) | Payload |
|---|---|---|---|
| 1 | TCP 40000 → 80 | HTTP | 64 random bytes |
| 2 | UDP 40000 → 53 | DNS | the same 64 random bytes |
| 3 | TCP 40000 → 25 | SMTP | the same 64 random bytes |
| 4 | TCP 40000 → 53 | DNS | `GET / HTTP/1.1` with `Host: example.com` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/BONUS-04_detection_traps/input.pcap --output TEST/BONUS-04_detection_traps/output.jsonl
```

## Expected result

- The run writes 4 events and exits with code 0. Every event has `status="ok"` and no errors.
- Packets 1 to 3: `app_protocol="UNKNOWN"`, `detection.method="none"`, and `application=null`. The port hint applies only to an empty payload (R5.5), and no payload rule matches random bytes.
- Packet 4: `app_protocol="HTTP"`, `detection.method="payload"`, `detection.rule="http_request"`. The method is `payload`, not `port+payload`, because the hint (DNS) and the payload (HTTP) disagree.
- The HTTP parser fills `application` for packet 4.

## Actual result

`output.jsonl` holds 4 events. `console.txt` holds the console summary and the exit code 0.

| `packet_id` | Direction | `app_protocol` | `detection.method` | `detection.confidence` | `detection.rule` | `application` |
|---|---|---|---|---|---|---|
| 1 | TCP → 80 | `UNKNOWN` | `none` | `low` | `""` | `null` |
| 2 | UDP → 53 | `UNKNOWN` | `none` | `low` | `""` | `null` |
| 3 | TCP → 25 | `UNKNOWN` | `none` | `low` | `""` | `null` |
| 4 | TCP → 53 | **`HTTP`** | **`payload`** | `high` | `http_request` | `GET /`, host `example.com` |

All 4 events have `status="ok"` and no errors. TCP and UDP are supported protocols, so only the application is unknown for packets 1 to 3 (R5.1).

Packet 2 shows why the DNS rule checks the structure. Bytes 2 and 3 of the random payload give opcode 9, and bytes 4 and 5 give a question count of 35 352. The rule accepts only opcode 0 to 2 and 1 to 16 questions, so it rejects the payload at the header.

Wireshark labels the same 4 packets as TCP, DNS, SMTP, and TCP. It labels the random bytes on port 53 as DNS and on port 25 as SMTP, because it selects a dissector by port. It does not recognise the HTTP request on port 53. The parser gives `UNKNOWN` to the random bytes on all three ports and `HTTP` to packet 4, because it decides from the payload.

## Verdict

PASS.
