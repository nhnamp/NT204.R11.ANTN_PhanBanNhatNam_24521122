# A3-T03 — Unsupported keyword

## Purpose

A rule outside the supported scope must get the status `unsupported` with a reason. It must not stop the run. This is test case 3 of the description. The case covers a keyword (`pcre`, `byte_test`), a protocol (`icmp`), and a variable (`$HOME_NET`).

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t03_unsupported_keyword/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host` header) | 101 |

`local.rules` holds 6 lines. Line 1 is a comment.

| Line | Rule | Out-of-scope item |
|---|---|---|
| 2 | sid 100301 | `pcre` |
| 3 | sid 100302 | `byte_test` |
| 4 | sid 100303 | Protocol `icmp` (with `itype`) |
| 5 | sid 100304 | Source address `$HOME_NET` |
| 6 | sid 100305 | Valid: `content:"GET "; depth:4` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T03_unsupported_keyword/input/traffic.pcap --rules-config TEST/assignment-03/A3-T03_unsupported_keyword/input/rules.toml --output TEST/assignment-03/A3-T03_unsupported_keyword/output/events.jsonl --flows-output TEST/assignment-03/A3-T03_unsupported_keyword/output/flows.jsonl --matches-output TEST/assignment-03/A3-T03_unsupported_keyword/output/matches.jsonl --rules-report TEST/assignment-03/A3-T03_unsupported_keyword/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0.
- `rules_report.jsonl` holds 5 lines. Lines 2 to 5 have `status="unsupported"` and `rule=null`. Line 6 has `status="valid"`.
- The reasons name the item: `keyword pcre`, `keyword byte_test`, `protocol icmp`, `variable $HOME_NET`.
- The console shows one warning for each of the 4 rules.
- The summary shows `rules valid: 1`, `rules invalid: 0`, `rules unsupported: 4`.
- The valid rule is the only candidate: `candidate rules: 1`. It matches `GET ` at position 0, so `rule matches: 1`.

## Actual result

The report lines 2 to 5 have `status="unsupported"`, `rule=null`, and these reasons:

| Report line | Reason |
|---|---|
| 2 | `keyword pcre` |
| 3 | `keyword byte_test` |
| 4 | `protocol icmp` |
| 5 | `variable $HOME_NET` |

Line 6 is `valid`. `console.txt` shows 4 warnings and the summary `rules valid: 1`, `rules invalid: 0`, `rules unsupported: 4`, `candidate rules: 1`, `rule matches: 1`, `engine errors: 0`. The exit code is 0. `matches.jsonl` holds one rule match: sid 100305, `GET ` at position 0.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 101 bytes       1 101 bytes     0.000000000         0.0000
```

Wireshark decodes one HTTP request on TCP port 80, with a 47-byte payload that starts with `GET `. The packet is TCP, so the `icmp` rule has no traffic to match even if the engine supported it. The expert and malformed filter finds no problem.

## Verdict

PASS. The 4 out-of-scope rules are `unsupported` with a reason, and the run ends with exit code 0. The valid rule still matches the packet.
