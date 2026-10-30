# A3-T13 — Multiple rule matches

## Purpose

One packet can match more than one rule. The engine must check every candidate and write one rule match for each rule that matches. It must not stop at the first match. This is test case 13 of the description (decision D9).

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t13_multiple_matches/`.

`traffic.pcap` (2 packets, both 10.0.0.1:40000 → 10.0.0.2:80, PSH and ACK):

| Packet | Time (s) | Payload (bytes) | Frame length (bytes) | Content |
|---|---|---|---|---|
| 1 | 0.0 | 82 | 136 | `POST /login HTTP/1.1`, a `Host` header, and the body `user=admin' OR 1=1;` |
| 2 | 0.5 | 47 | 101 | `GET /index.html HTTP/1.1`, a `Host` header |

`local.rules` holds 4 rules, all `tcp any any -> any 80`:

| Line | Sid | Priority | Content | Packet 1 | Packet 2 |
|---|---|---|---|---|---|
| 2 | 101301 | 2 | `POST` (`depth:4`), then `/login` (`distance:1; within:6`) | Match | No match |
| 3 | 101302 | 1 | `or 1=1` (`nocase`) | Match | No match |
| 4 | 101303 | 3 | `HTTP/1.1` | Match | Match |
| 5 | 101304 | 2 | `DELETE` (`depth:6`) | No match | No match |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T13_multiple_matches/input/traffic.pcap --rules-config TEST/assignment-03/A3-T13_multiple_matches/input/rules.toml --output TEST/assignment-03/A3-T13_multiple_matches/output/events.jsonl --flows-output TEST/assignment-03/A3-T13_multiple_matches/output/flows.jsonl --matches-output TEST/assignment-03/A3-T13_multiple_matches/output/matches.jsonl --rules-report TEST/assignment-03/A3-T13_multiple_matches/output/rules_report.jsonl
```

## Expected result

- Packet 1 matches three rules: 101301, 101302, and 101303. The engine writes three rule matches for this packet. Rule 101304 does not match.
- Packet 2 matches rule 101303 only.
- All 4 rules are candidates for both packets: `candidate rules: 8`. The pairs that do not match stop at the content: `rejected by content: 4` (101304 for both packets, 101301 and 101302 for packet 2).
- `rule matches: 4`. `matches.jsonl` holds 4 lines.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 2`, `candidate rules: 8`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 4`, `rule matches: 4`, `engine errors: 0`. The exit code is 0.

| Line of `matches.jsonl` | `packet_id` | `sid` | `priority` | `classtype` | `matched` |
|---|---|---|---|---|---|
| 1 | 1 | 101301 | 2 | `web-application-activity` | `POST` at 0, `/login` at 5 |
| 2 | 1 | 101302 | 1 | `web-application-attack` | `or 1=1` at 75 |
| 3 | 1 | 101303 | 3 | `misc-activity` | `HTTP/1.1` at 12 |
| 4 | 2 | 101303 | 3 | `misc-activity` | `HTTP/1.1` at 16 |

Packet 1 gives three rule matches, in the order of the sid.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 82  136 POST\ /login\ HTTP/1.1\ 
2 0.500000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         2 237 bytes       2 237 bytes     0.000000000         0.5000
```

Wireshark decodes packet 1 as `POST /login HTTP/1.1` with an 82-byte payload and packet 2 as `GET /index.html HTTP/1.1` with a 47-byte payload. Packet 1 holds `POST /login`, `OR 1=1`, and `HTTP/1.1`, and has no `DELETE`. Packet 2 holds `HTTP/1.1` only. This agrees with the table of the rules. The expert and malformed filter finds no problem.

## Verdict

PASS. Packet 1 gives three rule matches, one for each rule that matches, and the engine does not stop at the first one. The rule that does not match writes nothing.
