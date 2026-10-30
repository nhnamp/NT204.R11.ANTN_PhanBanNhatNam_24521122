# A3-T07 — Header mismatch

## Purpose

The engine must discard a rule that fails on the header before it matches the content. This is test case 7 of the description. The counters prove the order: `rejected by header` counts the rules, and `rejected by content` stays 0.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t07_header_mismatch/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host` header) | 101 |

`local.rules` holds 4 rules, all `tcp` with destination port 80 and `content:"GET "; depth:4`. The payload holds this content, so each rule would match if its header fitted. All 4 rules pass the index, because the protocol and the port fit.

| Line | Sid | Header | Header result |
|---|---|---|---|
| 3 | 100701 | `tcp 192.168.1.5 any -> any 80` | Fails: the source IP is 10.0.0.1 |
| 4 | 100702 | `tcp any any -> 172.16.0.0/12 80` | Fails: 10.0.0.2 is not in the CIDR |
| 5 | 100703 | `tcp 10.0.0.1 any -> 10.0.0.3 80` | Fails: the destination IP is 10.0.0.2 |
| 6 | 100704 | `tcp 10.0.0.0/24 any -> 10.0.0.2 80` | Fits: a control rule |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T07_header_mismatch/input/traffic.pcap --rules-config TEST/assignment-03/A3-T07_header_mismatch/input/rules.toml --output TEST/assignment-03/A3-T07_header_mismatch/output/events.jsonl --flows-output TEST/assignment-03/A3-T07_header_mismatch/output/flows.jsonl --matches-output TEST/assignment-03/A3-T07_header_mismatch/output/matches.jsonl --rules-report TEST/assignment-03/A3-T07_header_mismatch/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0.
- The index returns the 4 rules: `candidate rules: 4`.
- Rules 100701, 100702, and 100703 fail on the address, so `rejected by header: 3`.
- The matcher stops these rules at the header, so the content is not checked: `rejected by content: 0`. The content would have matched.
- The control rule 100704 matches: `rule matches: 1`. `matches.jsonl` holds only sid 100704.

## Actual result

The summary shows `records evaluated: 1`, `candidate rules: 4`, `rejected by header: 3`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 0`, `rule matches: 1`, `engine errors: 0`. The exit code is 0. `matches.jsonl` holds one rule match: sid 100704, `GET ` at position 0.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 101 bytes       1 101 bytes     0.000000000         0.0000
```

Wireshark shows the source 10.0.0.1 and the destination 10.0.0.2. These addresses are not 192.168.1.5, not in 172.16.0.0/12, and not 10.0.0.3, so the 3 rules fail on the header. The addresses are in 10.0.0.0/24 and match 10.0.0.2, so the control rule fits. The payload starts with `GET `, so the content of all 4 rules is present. The expert and malformed filter finds no problem.

## Verdict

PASS. Three rules are discarded on the header with `rejected by content: 0`, although their content is in the payload. The control rule shows that the packet does match a rule with the right header.
