# A3-T10 — Content with offset and depth

## Purpose

`offset` and `depth` must limit the part of the payload where the engine looks for a content. A match must be only inside this region. This is test case 10 of the description. Each pair of rules has one rule that fits the region and one that does not.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t10_offset_depth/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 28 (`GET /index.html HTTP/1.1`, CR LF CR LF) | 82 |

The word `index` is in the payload once. It occupies bytes 5 to 9, so it starts at byte 5 and ends at byte 10.

`local.rules` holds 6 rules, all `tcp any any -> any 80` with `content:"index"`:

| Line | Sid | Option | Region searched | Expected |
|---|---|---|---|---|
| 2 | 101001 | `offset:5` | From byte 5 | Match |
| 3 | 101002 | `offset:6` | From byte 6 | No match: the word starts at byte 5 |
| 4 | 101003 | `depth:10` | Bytes 0 to 9 | Match: the word ends at byte 10 (the limit) |
| 5 | 101004 | `depth:9` | Bytes 0 to 8 | No match: the word needs 10 bytes |
| 6 | 101005 | `offset:5; depth:5` | Bytes 5 to 9 | Match: exactly the word |
| 7 | 101006 | `offset:2; depth:5` | Bytes 2 to 6 | No match: the region holds `T /in` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T10_offset_depth/input/traffic.pcap --rules-config TEST/assignment-03/A3-T10_offset_depth/input/rules.toml --output TEST/assignment-03/A3-T10_offset_depth/output/events.jsonl --flows-output TEST/assignment-03/A3-T10_offset_depth/output/flows.jsonl --matches-output TEST/assignment-03/A3-T10_offset_depth/output/matches.jsonl --rules-report TEST/assignment-03/A3-T10_offset_depth/output/rules_report.jsonl
```

## Expected result

- Rules 101001, 101003, and 101005 match, each with the position 5.
- Rules 101002, 101004, and 101006 do not match.
- The summary shows `candidate rules: 6`, `rejected by header: 0`, `rejected by content: 3`, `rule matches: 3`.
- `matches.jsonl` holds the sids 101001, 101003, and 101005.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 1`, `candidate rules: 6`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 3`, `rule matches: 3`, `engine errors: 0`. The exit code is 0.

`matches.jsonl` holds the sids 101001, 101003, and 101005, each with `content "index"` at position 5. The sids 101002, 101004, and 101006 have no rule match.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 28  82 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 82 bytes        1 82 bytes      0.000000000         0.0000
```

Wireshark decodes the request `GET /index.html HTTP/1.1`, and the TCP payload has 28 bytes. In the line `GET /index.html`, the characters `GET ` take bytes 0 to 3, the slash is byte 4, and `index` takes bytes 5 to 9. This position decides the table above. The expert and malformed filter finds no problem.

## Verdict

PASS. The rules whose region holds the word match with position 5, and the rules whose region cuts the word or starts after it do not match.
