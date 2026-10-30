# A3-T09 — Content with and without nocase

## Purpose

`content` must be case sensitive. With `nocase`, it must ignore the case. This is test case 9 of the description. The payload holds `Admin` with a capital letter. Only the `nocase` rule can find the lowercase word `admin`.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t09_content_nocase/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 29 (`GET /Admin/Login HTTP/1.1`) | 83 |

The word `Admin` starts at byte 5.

`local.rules` holds 3 rules, all `tcp any any -> any 80`:

| Line | Sid | Option | Meaning |
|---|---|---|---|
| 2 | 100901 | `content:"admin"` | Lowercase, case sensitive |
| 3 | 100902 | `content:"admin"; nocase` | Lowercase, ignore the case |
| 4 | 100903 | `content:"Admin"` | Same case as the payload, case sensitive |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T09_content_nocase/input/traffic.pcap --rules-config TEST/assignment-03/A3-T09_content_nocase/input/rules.toml --output TEST/assignment-03/A3-T09_content_nocase/output/events.jsonl --flows-output TEST/assignment-03/A3-T09_content_nocase/output/flows.jsonl --matches-output TEST/assignment-03/A3-T09_content_nocase/output/matches.jsonl --rules-report TEST/assignment-03/A3-T09_content_nocase/output/rules_report.jsonl
```

## Expected result

- Rule 100901 does not match: `admin` and `Admin` differ in the first letter.
- Rule 100902 matches: `nocase` ignores the case. The position is 5.
- Rule 100903 matches: the case is the same. The position is 5. This rule shows that a case sensitive search still finds an exact match.
- The summary shows `candidate rules: 3`, `rejected by header: 0`, `rejected by content: 1`, `rule matches: 2`.
- `matches.jsonl` holds the sids 100902 and 100903.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 1`, `candidate rules: 3`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 1`, `rule matches: 2`, `engine errors: 0`. The exit code is 0.

`matches.jsonl` holds sid 100902 (`content "admin"` at position 5) and sid 100903 (`content "Admin"` at position 5). Sid 100901 has no rule match.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 29  83 GET\ /Admin/Login\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 83 bytes        1 83 bytes      0.000000000         0.0000
```

Wireshark decodes the request `GET /Admin/Login HTTP/1.1`. The TCP payload has 29 bytes. The path holds `Admin` with a capital A after `GET /`, which is byte 5. The expert and malformed filter finds no problem.

## Verdict

PASS. Only the `nocase` rule finds the lowercase text in the payload with another case. The case sensitive rule with the same case also matches, and the case sensitive rule with another case does not.
