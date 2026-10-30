# A3-T01 — Rule file with comments and blank lines

## Purpose

The rule loader must skip comments and blank lines. Only the real rule lines go to the parser. This is test case 1 of the description. The rules report must hold one line for each rule line and none for a comment or a blank line.

## Input

`input/` holds three files. The script `tests/fixtures/build_pcaps.py` generates `traffic.pcap` with fixed times. The other two files are copies from `tests/fixtures/rules/t01_rule_file_comments/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host` header) | 101 |

`local.rules` holds 12 lines:

| Line | Content |
|---|---|
| 1 | A comment |
| 2 | A blank line |
| 3 | A comment |
| 4 | A comment that holds a whole rule (sid 100199) |
| 5 | A blank line |
| 6 | A comment with leading white space |
| 7 | A blank line |
| 8 | Rule 100101: `tcp any any -> any 80`, `content:"GET "; depth:4` |
| 9 | A blank line |
| 10 | Rule 100102: `tcp any any -> any 80`, `content:"POST "; depth:5` |
| 11 | A line with one tab |
| 12 | Rule 100103: `udp any any -> any 53`, a DNS name in `content` |

`rules.toml` enables `local.rules`.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T01_rule_file_comments/input/traffic.pcap --rules-config TEST/assignment-03/A3-T01_rule_file_comments/input/rules.toml --output TEST/assignment-03/A3-T01_rule_file_comments/output/events.jsonl --flows-output TEST/assignment-03/A3-T01_rule_file_comments/output/flows.jsonl --matches-output TEST/assignment-03/A3-T01_rule_file_comments/output/matches.jsonl --rules-report TEST/assignment-03/A3-T01_rule_file_comments/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0.
- `rules_report.jsonl` holds 3 lines, for lines 8, 10, and 12 of `local.rules`. Each has `status="valid"`. No line is for a comment, a blank line, or sid 100199.
- The summary shows `rules valid: 3`, `rules invalid: 0`, `rules unsupported: 0`, `rules disabled: 0`.
- The pcap has 1 TCP record. Rule 100103 is a `udp` rule, so the index does not return it. `records evaluated: 1` and `candidate rules: 2`.
- Rule 100101 matches: the payload starts with `GET `. Rule 100102 does not match: the content `POST ` is not in the payload. `rejected by content: 1` and `rule matches: 1`.
- `matches.jsonl` holds 1 rule match, for sid 100101, with the content at position 0.

## Actual result

`output/` holds `events.jsonl` (1 event), `flows.jsonl` (1 flow), `matches.jsonl` (1 rule match), and `rules_report.jsonl` (3 lines). `console.txt` holds the summary and the exit code 0.

| Item | Value |
|---|---|
| Report lines (`line`, `status`) | (8, `valid`), (10, `valid`), (12, `valid`) |
| `rules valid`, `rules invalid`, `rules unsupported`, `rules disabled` | 3, 0, 0, 0 |
| `records evaluated`, `candidate rules` | 1, 2 |
| `rejected by header`, `rejected by flow`, `rejected by packet options`, `rejected by content` | 0, 0, 0, 1 |
| `rule matches`, `engine errors` | 1, 0 |
| Rule match | sid 100101, `matched` = `content "GET "` at position 0 |

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the IP, TCP, and UDP checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 101 bytes       1 101 bytes     0.000000000         0.0000
```

Wireshark decodes one HTTP request from 10.0.0.1:40000 to 10.0.0.2:80. The TCP payload is 47 bytes and the frame is 101 bytes. The expert and malformed filter finds no problem. The payload starts with `GET `, so rule 100101 must match. The payload has no `POST `, so rule 100102 must not match.

## Verdict

PASS. The report has exactly 3 lines, so the comments and the blank lines did not reach the parser. The counters and the rule match agree with the expected result, and the pcap decodes as the table says.
