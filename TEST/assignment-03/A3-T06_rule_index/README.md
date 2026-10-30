# A3-T06 — Rule index

## Purpose

The index must return only the rules that can fit a record, by protocol and port. It must not scan all rules. This is test case 6 of the description. The case uses one rule for each kind of index list: `ip`, `tcp` with a port, `udp` with a port, `tcp` with `any`, and `udp` with a port range.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t06_rule_index/`.

`traffic.pcap` (3 packets, each with the 11-byte payload `index-probe`):

| Packet | Time (s) | Direction | Protocol | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | TCP (PSH, ACK) | 11 | 65 |
| 2 | 0.5 | 10.0.0.1:40000 → 10.0.0.2:53 | UDP | 11 | 53 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:22 | TCP (PSH, ACK) | 11 | 65 |

`local.rules` holds 5 rules, all with `content:"index-probe"`:

| Line | Sid | Header | Index list |
|---|---|---|---|
| 2 | 100601 | `ip any any -> any any` | `ip` list: every TCP and UDP record |
| 3 | 100602 | `tcp any any -> any 80` | Bucket of TCP port 80 |
| 4 | 100603 | `udp any any -> any 53` | Bucket of UDP port 53 |
| 5 | 100604 | `tcp any any -> any any` | Wildcard list of TCP |
| 6 | 100605 | `udp any 1024: -> any any` | Wildcard list of UDP (a range goes there) |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T06_rule_index/input/traffic.pcap --rules-config TEST/assignment-03/A3-T06_rule_index/input/rules.toml --output TEST/assignment-03/A3-T06_rule_index/output/events.jsonl --flows-output TEST/assignment-03/A3-T06_rule_index/output/flows.jsonl --matches-output TEST/assignment-03/A3-T06_rule_index/output/matches.jsonl --rules-report TEST/assignment-03/A3-T06_rule_index/output/rules_report.jsonl
```

## Expected result

The candidate set of each record:

| Packet | Candidate rules | Count |
|---|---|---|
| 1 (TCP, port 80) | 100601, 100602, 100604 | 3 |
| 2 (UDP, port 53) | 100601, 100603, 100605 | 3 |
| 3 (TCP, port 22) | 100601, 100604 | 2 |
| Sum | | 8 |

- Rule 100602 is not a candidate for packet 3, and rule 100603 is not a candidate for packet 1. The port buckets exclude them.
- No `udp` rule is a candidate for a TCP record, and no `tcp` rule for a UDP record.
- `records evaluated: 3` and `candidate rules: 8`. The sum of the table equals the counter.
- Each candidate fits the header and holds `index-probe`, so `rejected by header: 0`, `rejected by content: 0`, and `rule matches: 8`.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 3`, `candidate rules: 8`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 0`, `rule matches: 8`, `engine errors: 0`. The exit code is 0. `matches.jsonl` shows the candidate set of each packet, because every candidate matches:

| Packet | Sids in `matches.jsonl` |
|---|---|
| 1 | 100601, 100602, 100604 |
| 2 | 100601, 100603, 100605 |
| 3 | 100601, 100604 |

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 TCP 40000  80  ·······AP··· 11  65 40000\ →\ 80\ [PSH,\ ACK]\ Seq=1\ Ack=1\ Win=8192\ Len=11
2 0.500000000 10.0.0.1 10.0.0.2 DNS  40000  53   19 53 Unknown\ operation\ (12)\ 0x696e[Malformed\ Packet]
3 1.000000000 10.0.0.1 10.0.0.2 SSH 40000  22  ·······AP··· 11  65 Client:\ Encrypted\ packet\ (len=11)
-- problems (expert or malformed, checksums checked):
       1
10.0.0.1:40000             <-> 10.0.0.2:53                      0 0 bytes         1 53 bytes        1 53 bytes      0.500000000         0.0000
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 65 bytes        1 65 bytes      0.000000000         0.0000
10.0.0.1:40000             <-> 10.0.0.2:22                      0 0 bytes         1 65 bytes        1 65 bytes      1.000000000         0.0000
```

Wireshark shows a TCP packet to port 80, a UDP datagram to port 53, and a TCP packet to port 22. The protocols and ports agree with the input table, and each payload has 11 bytes. These facts decide the candidate sets above.

The expert and malformed filter reports one line: the DNS dissector marks packet 2 as malformed, because the payload `index-probe` is not a DNS message. The IP and UDP headers are correct, and the checksums are valid. The case tests the index and not DNS, so the finding has no effect on the result.

## Verdict

PASS. The `candidate rules` counter (8) equals the sum of the candidate sets (3 + 3 + 2). The port buckets and the protocol lists return the expected rules.
