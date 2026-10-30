# A3-T02 — Invalid rule

## Purpose

A rule with a syntax error must be marked `invalid` with a reason. The engine must go on: it loads the other rules and matches the traffic with the valid ones. This is test case 2 of the description.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t02_invalid_rule/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host: example.com` header) | 101 |

`local.rules` holds 8 lines. Line 1 is a comment.

| Line | Rule | Fault |
|---|---|---|
| 2 | sid missing | No `sid` |
| 3 | sid 100202 | Destination port 70000 |
| 4 | sid 100203 | `content:"GET /index"; depth:3`, and `depth` is smaller than the pattern (10 bytes) |
| 5 | sid 100204 | The header has 6 fields, not 7 |
| 6 | sid 100201 | Valid: `content:"GET "; depth:4` |
| 7 | sid 100201 | Same sid as line 6 |
| 8 | sid 100205 | Valid: `content:"Host|3A| example.com"` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T02_invalid_rule/input/traffic.pcap --rules-config TEST/assignment-03/A3-T02_invalid_rule/input/rules.toml --output TEST/assignment-03/A3-T02_invalid_rule/output/events.jsonl --flows-output TEST/assignment-03/A3-T02_invalid_rule/output/flows.jsonl --matches-output TEST/assignment-03/A3-T02_invalid_rule/output/matches.jsonl --rules-report TEST/assignment-03/A3-T02_invalid_rule/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0. The faults stop no rule and no packet.
- `rules_report.jsonl` holds 7 lines, for lines 2 to 8. Lines 2, 3, 4, 5, and 7 have `status="invalid"` and a reason. Lines 6 and 8 have `status="valid"`.
- The reasons name the fault: a missing sid, a port above 65535, a `depth` smaller than the pattern, a header with 6 fields instead of 7, and a duplicate sid 100201.
- The console shows one warning for each invalid rule, with file, line, and reason.
- The summary shows `rules valid: 2` and `rules invalid: 5`.
- The index returns the 2 valid rules for the TCP record, so `candidate rules: 2`. Both match, so `rule matches: 2`.
- `matches.jsonl` holds sid 100201 with `GET ` at position 0 and sid 100205 with `Host|3A| example.com` at position 26. The first line of the payload is 26 bytes (`GET /index.html HTTP/1.1` and CR LF).

## Actual result

`console.txt` shows 5 warnings, and the summary shows `rules valid: 2`, `rules invalid: 5`, `candidate rules: 2`, `rule matches: 2`, and `engine errors: 0`. The exit code is 0.

| Report line | `status` | `reason` |
|---|---|---|
| 2 | `invalid` | `missing sid` |
| 3 | `invalid` | `port above 65535 in 70000` |
| 4 | `invalid` | `depth is smaller than the pattern` |
| 5 | `invalid` | `the header needs 7 fields, found 6` |
| 6 | `valid` | `null` |
| 7 | `invalid` | `duplicate sid 100201` |
| 8 | `valid` | `null` |

Each `invalid` line has `rule=null`. `matches.jsonl` holds 2 rule matches: sid 100201 at position 0 and sid 100205 at position 26.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 101 bytes       1 101 bytes     0.000000000         0.0000
```

Wireshark decodes one HTTP request with a 47-byte TCP payload. The payload holds `GET ` at byte 0 and `Host: example.com` at byte 26, so the two valid rules must match. The expert and malformed filter finds no problem.

## Verdict

PASS. Five rules are `invalid`, each with its own reason, and the duplicate sid is rejected after the first one. The run ends with exit code 0, and the two valid rules still match the packet.
