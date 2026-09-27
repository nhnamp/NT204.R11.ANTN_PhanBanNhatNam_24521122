# TC-07 — DNS query

## Purpose

The parser must parse a DNS query: the queried domain name and the query type.

## Input

`input.pcap` is a copy of `tests/fixtures/dns_query.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

The file holds one UDP datagram from 10.0.0.1:40000 to 10.0.0.2:53. Its payload is a 29-byte DNS message:

```text
12 34                              transaction ID 0x1234
01 00                              flags: QR=0 (query), opcode 0, RD=1
00 01 00 00 00 00 00 00            QDCOUNT 1, ANCOUNT 0, NSCOUNT 0, ARCOUNT 0
07 65 78 61 6d 70 6c 65            label "example" (7 bytes)
03 63 6f 6d 00                     label "com" (3 bytes), then the zero label
00 01                              QTYPE 1 (A)
00 01                              QCLASS 1 (IN)
```

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-07_dns_query/input.pcap --output TEST/TC-07_dns_query/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `app_protocol` is `"DNS"`. The payload rule and the port agree: `detection.method="port+payload"`, `detection.rule="dns_udp"`.
- `application.is_response` is `false`, and `application.flags` is `["RD"]`.
- `application.questions` holds 1 question: name `example.com`, `qtype=1`, `qtype_name="A"`, `qclass=1`.
- `application.answers` is empty.
- The event has `status="ok"`, `application.partial=false`, and no errors.

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `app_protocol` | `DNS` |
| `detection` | `method="port+payload"`, `confidence="high"`, `rule="dns_udp"` |
| `application.transaction_id` | 4660 (`0x1234`) |
| `application.is_response` | `false` |
| `application.opcode` | 0 |
| `application.flags` | `["RD"]` |
| `application.rcode`, `application.rcode_name` | 0, `NOERROR` |
| `application.qdcount`, `ancount`, `nscount`, `arcount` | 1, 0, 0, 0 |
| `application.questions[0].name` | `example.com` |
| `application.questions[0].qtype`, `qtype_name` | 1, `A` |
| `application.questions[0].qclass` | 1 |
| `application.answers` | `[]` |
| `application.partial` | `false` |
| `payload_len` | 29 |
| `status`, `errors` | `ok`, `[]` |

`payload_preview` holds the whole 29-byte message, because it is shorter than the 64-byte preview limit. The hex matches the layout in the Input section.

Wireshark shows the same query: `Standard query 0x1234 A example.com`, flags `0x0100` (recursion desired), 1 question and 0 records in the other sections, and the question `example.com`, type A, class IN. Its UDP length is 37, equal to the 8-byte UDP header plus the 29-byte message.

## Verdict

PASS.
