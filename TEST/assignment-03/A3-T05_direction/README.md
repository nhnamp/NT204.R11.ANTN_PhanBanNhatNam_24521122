# A3-T05 — Rule direction

## Purpose

A `->` rule must match only the packets that go from the source to the destination of the rule. A `<>` rule must match the packets of both directions. This is test case 5 of the description. All rules have the same content, so only the header can tell the two packets apart.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t05_direction/`.

`traffic.pcap` (2 packets, one HTTP request and its response):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host` header) | 101 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | PSH, ACK | 38 (`HTTP/1.1 200 OK`, a `Content-Length` header) | 92 |

Both payloads hold `HTTP/1.1`: at byte 16 in packet 1 and at byte 0 in packet 2.

`local.rules` holds 3 rules, all with `content:"HTTP/1.1"`:

| Line | Sid | Header | Meaning |
|---|---|---|---|
| 3 | 100501 | `tcp 10.0.0.1 any -> 10.0.0.2 80` | One way, client to server |
| 4 | 100502 | `tcp 10.0.0.1 any <> 10.0.0.2 80` | Both ways |
| 5 | 100503 | `tcp 10.0.0.2 80 -> 10.0.0.1 any` | One way, server to client |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T05_direction/input/traffic.pcap --rules-config TEST/assignment-03/A3-T05_direction/input/rules.toml --output TEST/assignment-03/A3-T05_direction/output/events.jsonl --flows-output TEST/assignment-03/A3-T05_direction/output/flows.jsonl --matches-output TEST/assignment-03/A3-T05_direction/output/matches.jsonl --rules-report TEST/assignment-03/A3-T05_direction/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0.
- Rule 100501 matches packet 1 only. The response goes the other way, so the header of the response does not fit.
- Rule 100502 matches packet 1 and packet 2. The reversed side of a `<>` rule also fits.
- Rule 100503 matches packet 2 only.
- The index returns all 3 rules for each packet, so `candidate rules: 6`. Two pairs fail on the header (100501 with packet 2, and 100503 with packet 1), so `rejected by header: 2`. `rejected by content: 0`, and `rule matches: 4`.
- `matches.jsonl` holds 4 rule matches: (packet 1, 100501), (packet 1, 100502), (packet 2, 100502), (packet 2, 100503).

## Actual result

| Packet | Rule matches (sid) |
|---|---|
| 1 | 100501, 100502 |
| 2 | 100502, 100503 |

The summary shows `records evaluated: 2`, `candidate rules: 6`, `rejected by header: 2`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 0`, `rule matches: 4`, `engine errors: 0`. The exit code is 0. The `<>` rule 100502 gives a rule match for each direction. The `direction` field of its two rule matches is `forward` (packet 1) and `backward` (packet 2).

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
2 0.500000000 10.0.0.2 10.0.0.1 HTTP 80  40000  ·······AP··· 38  92 HTTP/1.1\ 200\ OK\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      1 92 bytes        1 101 bytes       2 193 bytes     0.000000000         0.5000
```

Wireshark shows the request from 10.0.0.1:40000 to 10.0.0.2:80 and the response from 10.0.0.2:80 to 10.0.0.1:40000. It shows one TCP conversation with one frame in each direction. The directions and the 47-byte and 38-byte payloads agree with the input table. The expert and malformed filter finds no problem.

## Verdict

PASS. The `->` rules match one packet each, in the direction of the rule. The `<>` rule matches both packets.
