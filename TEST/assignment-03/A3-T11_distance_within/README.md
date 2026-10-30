# A3-T11 — Content with distance and within

## Purpose

`distance` and `within` must place the second content relative to the end of the first content. The engine must not stop at a wrong first occurrence of the first content. This is test case 11 of the description.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t11_distance_within/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 19 (`id=1&id=22&name=bob`) | 73 |

The byte positions of the payload:

| Bytes | 0 to 3 | 4 | 5 to 7 | 8 to 9 | 10 | 11 to 15 | 16 to 18 |
|---|---|---|---|---|---|---|---|
| Text | `id=1` | `&` | `id=` | `22` | `&` | `name=` | `bob` |

The text `id=` occurs twice: at bytes 0 to 2 and at bytes 5 to 7.

`local.rules` holds 4 rules, all `tcp any any -> any 80` with two contents:

| Line | Sid | Contents | Expected |
|---|---|---|---|
| 2 | 101101 | `id=`, then `22` with `distance:0; within:2` | Match, but only through the second `id=` |
| 3 | 101102 | `id=`, then `bob` with `distance:0; within:3` | No match |
| 4 | 101103 | `22`, then `name` with `distance:1; within:4` | Match |
| 5 | 101104 | `22`, then `name` with `distance:2; within:4` | No match |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T11_distance_within/input/traffic.pcap --rules-config TEST/assignment-03/A3-T11_distance_within/input/rules.toml --output TEST/assignment-03/A3-T11_distance_within/output/events.jsonl --flows-output TEST/assignment-03/A3-T11_distance_within/output/flows.jsonl --matches-output TEST/assignment-03/A3-T11_distance_within/output/matches.jsonl --rules-report TEST/assignment-03/A3-T11_distance_within/output/rules_report.jsonl
```

## Expected result

- Rule 101101: the first `id=` ends at byte 3. The region of `22` is bytes 3 to 4 (`1&`), which does not hold `22`. This first occurrence is wrong. The second `id=` ends at byte 8. The region is bytes 8 to 9, which is `22`. The rule matches, with `id=` at position 5 and `22` at position 8.
- Rule 101102: `bob` is at byte 16. The regions after the two `id=` are bytes 3 to 5 and bytes 8 to 10. Neither holds `bob`. The rule does not match.
- Rule 101103: `22` ends at byte 10. With `distance:1` the region starts at byte 11 and has 4 bytes, so it is `name`. The rule matches, with `22` at position 8 and `name` at position 11.
- Rule 101104: with `distance:2` the region starts at byte 12 and holds `ame=`. The rule does not match.
- The summary shows `candidate rules: 4`, `rejected by content: 2`, `rule matches: 2`.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 1`, `candidate rules: 4`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 0`, `rejected by content: 2`, `rule matches: 2`, `engine errors: 0`. The exit code is 0.

| Sid | Rule match | Positions |
|---|---|---|
| 101101 | Yes | `id=` at 5, `22` at 8 |
| 101102 | No | |
| 101103 | Yes | `22` at 8, `name` at 11 |
| 101104 | No | |

For rule 101101 the engine reports `id=` at position 5. So it did not keep the first occurrence at position 0.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 TCP 40000  80  ·······AP··· 19  73 40000\ →\ 80\ [PSH,\ ACK]\ Seq=1\ Ack=1\ Win=8192\ Len=19
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 73 bytes        1 73 bytes      0.000000000         0.0000
```

Wireshark shows a TCP packet to port 80 with a 19-byte payload and a 73-byte frame. The payload bytes are `id=1&id=22&name=bob`, so the positions in the table above hold. The expert and malformed filter finds no problem.

## Verdict

PASS. Rule 101101 matches although its first `id=` is a wrong anchor, because the engine tries the second `id=`. The `distance` limit of rules 101103 and 101104 decides between a match and no match.
