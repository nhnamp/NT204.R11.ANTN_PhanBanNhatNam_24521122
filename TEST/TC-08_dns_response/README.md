# TC-08 — DNS response

## Purpose

The parser must parse a DNS response with at least one answer record.

## Input

`input.pcap` is a copy of `tests/fixtures/dns_response.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

The file holds one UDP datagram from the server 10.0.0.2:53 to the client 10.0.0.1:40000. It answers the query of TC-07. Its payload is a 56-byte DNS message:

```text
12 34                              transaction ID 0x1234, the same as the query
81 80                              flags: QR=1 (response), opcode 0, RD=1, RA=1, RCODE 0
00 01 00 01 00 00 00 00            QDCOUNT 1, ANCOUNT 1, NSCOUNT 0, ARCOUNT 0
07 example 03 com 00 00 01 00 01   question: example.com, type A, class IN (17 bytes)
07 example 03 com 00               answer name: example.com (13 bytes)
00 01 00 01                        TYPE 1 (A), CLASS 1 (IN)
00 00 01 2c                        TTL 300 seconds
00 04                              RDLENGTH 4
5d b8 d8 22                        RDATA 93.184.216.34
```

The answer repeats the full name. It does not use a compression pointer to the question, because Scapy builds it without compression. The unit tests in `tests/test_dns.py` cover compressed names.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-08_dns_response/input.pcap --output TEST/TC-08_dns_response/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `app_protocol` is `"DNS"`, with `detection.method="port+payload"` and `detection.rule="dns_udp"`. The port hint comes from the source port 53.
- `application.is_response` is `true`, `application.flags` is `["RD", "RA"]`, and `application.rcode_name` is `NOERROR`.
- `application.answers` holds 1 record: name `example.com`, type `A`, class 1, TTL 300, and address `93.184.216.34`.
- The event has `status="ok"`, `application.partial=false`, and no errors.

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `app_protocol` | `DNS` |
| `detection` | `method="port+payload"`, `confidence="high"`, `rule="dns_udp"` |
| `application.transaction_id` | 4660 (`0x1234`) |
| `application.is_response` | `true` |
| `application.flags` | `["RD", "RA"]` |
| `application.rcode`, `application.rcode_name` | 0, `NOERROR` |
| `application.qdcount`, `ancount`, `nscount`, `arcount` | 1, 1, 0, 0 |
| `application.questions[0]` | `example.com`, `A` (1), class 1 |
| `application.answers[0].name` | `example.com` |
| `application.answers[0].type`, `type_name` | 1, `A` |
| `application.answers[0].rclass` | 1 |
| `application.answers[0].ttl` | 300 |
| `application.answers[0].rdata` | `93.184.216.34` |
| `application.partial` | `false` |
| `payload_len` | 56 |
| `status`, `errors` | `ok`, `[]` |

`payload_preview` holds the whole 56-byte message, because it is shorter than the 64-byte preview limit. Its last 4 bytes, `5db8d822`, are the address `93.184.216.34`.

Wireshark shows the same response: `Standard query response 0x1234 A example.com A 93.184.216.34`, flags `0x8180` (recursion desired, recursion available, no error), 1 question and 1 answer. The answer is `example.com`, type A, class IN, TTL 300, data length 4, and address `93.184.216.34`. Its UDP length is 64, equal to the 8-byte UDP header plus the 56-byte message.

## Verdict

PASS.
