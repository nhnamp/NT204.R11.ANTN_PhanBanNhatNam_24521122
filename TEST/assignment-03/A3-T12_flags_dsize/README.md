# A3-T12 — TCP flags and dsize

## Purpose

`flags` must compare the TCP flags of the packet with the rule, with the modifiers `+` and `!`, and the value `0`. `dsize` must compare the payload length with `N`, `>N`, `<N`, and `N<>M`. This is test case 12 of the description. The packets sit on the limits of the `dsize` forms (10 and 100).

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t12_flags_dsize/`.

`traffic.pcap` (6 probe packets, all 10.0.0.1:50000 → 10.0.0.2:4000):

| Packet | Time (s) | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|
| 1 | 0.0 | SYN | 0 | 54 |
| 2 | 0.5 | SYN, ACK | 0 | 54 |
| 3 | 1.0 | PSH, ACK | 10 | 64 |
| 4 | 1.5 | ACK | 0 | 54 |
| 5 | 2.0 | PSH, ACK | 100 | 154 |
| 6 | 2.5 | none | 0 | 54 |

The packets are probes of flag and size combinations. They do not form a valid TCP session.

`local.rules` holds 10 rules, all `tcp any any -> any 4000` and with no content:

| Line | Sid | Option | Expected packets |
|---|---|---|---|
| 2 | 101201 | `flags:S` (exactly SYN) | 1 |
| 3 | 101202 | `flags:S+` (SYN and any other flag) | 1, 2 |
| 4 | 101203 | `flags:PA` (exactly PSH and ACK) | 3, 5 |
| 5 | 101204 | `flags:!S` (SYN not set) | 3, 4, 5, 6 |
| 6 | 101205 | `flags:0` (no flag) | 6 |
| 7 | 101206 | `dsize:10` | 3 |
| 8 | 101207 | `dsize:>10` | 5 |
| 9 | 101208 | `dsize:<10` | 1, 2, 4, 6 |
| 10 | 101209 | `dsize:10<>100` (both limits included) | 3, 5 |
| 11 | 101210 | `dsize:>100` | none |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T12_flags_dsize/input/traffic.pcap --rules-config TEST/assignment-03/A3-T12_flags_dsize/input/rules.toml --output TEST/assignment-03/A3-T12_flags_dsize/output/events.jsonl --flows-output TEST/assignment-03/A3-T12_flags_dsize/output/flows.jsonl --matches-output TEST/assignment-03/A3-T12_flags_dsize/output/matches.jsonl --rules-report TEST/assignment-03/A3-T12_flags_dsize/output/rules_report.jsonl
```

## Expected result

- The limits: `dsize:10` matches the 10-byte packet. `dsize:>10` and `dsize:<10` do not match it. `dsize:10<>100` matches both the 10-byte and the 100-byte packet. `dsize:>100` does not match the 100-byte packet.
- The packets of the last column of the table above match each rule. In total, 18 pairs of a packet and a rule match: 1 + 2 + 2 + 4 + 1 + 1 + 1 + 4 + 2 + 0.
- All 10 rules are candidates for all 6 packets: `candidate rules: 60`. The header always fits, so `rejected by header: 0`. The 42 other pairs stop at `flags` or `dsize`: `rejected by packet options: 42`. There is no content, so `rejected by content: 0`.
- `rule matches: 18`. The run exits with code 0.

## Actual result

The summary shows `records evaluated: 6`, `candidate rules: 60`, `rejected by header: 0`, `rejected by flow: 0`, `rejected by packet options: 42`, `rejected by content: 0`, `rule matches: 18`, `engine errors: 0`. The exit code is 0.

`matches.jsonl` holds 18 rule matches. The matched packets of each rule:

| Sid | Packets in `matches.jsonl` | As expected |
|---|---|---|
| 101201 | 1 | Yes |
| 101202 | 1, 2 | Yes |
| 101203 | 3, 5 | Yes |
| 101204 | 3, 4, 5, 6 | Yes |
| 101205 | 6 | Yes |
| 101206 | 3 | Yes |
| 101207 | 5 | Yes |
| 101208 | 1, 2, 4, 6 | Yes |
| 101209 | 3, 5 | Yes |
| 101210 | none | Yes |

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ··········S· 0  54 50000\ →\ 4000\ [SYN]\ Seq=0\ Win=8192\ Len=0
2 0.500000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ·······A··S· 0  54 [TCP\ Port\ numbers\ reused]\ 50000\ →\ 4000\ [SYN,\ ACK]\ Seq=0\ Ack=1\ Win=8192\ Len=0
3 1.000000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ·······AP··· 10  64 50000\ →\ 4000\ [PSH,\ ACK]\ Seq=1\ Ack=1\ Win=8192\ Len=10
4 1.500000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ·······A···· 0  54 [TCP\ Dup\ ACK\ 0#1]\ 50000\ →\ 4000\ [ACK]\ Seq=11\ Ack=1\ Win=8192\ Len=0
5 2.000000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ·······AP··· 100  154 50000\ →\ 4000\ [PSH,\ ACK]\ Seq=11\ Ack=1\ Win=8192\ Len=100
6 2.500000000 10.0.0.1 10.0.0.2 TCP 50000  4000  ············ 0  54 [TCP\ Dup\ ACK\ 0#2]\ 50000\ →\ 4000\ [<None>]\ Seq=111\ Win=8192\ Len=0
-- problems (expert or malformed, checksums checked):
       3
10.0.0.1:50000             <-> 10.0.0.2:4000                    0 0 bytes         5 380 bytes       5 380 bytes     0.500000000         2.0000
10.0.0.1:50000             <-> 10.0.0.2:4000                    0 0 bytes         1 54 bytes        1 54 bytes      0.000000000         0.0000
```

Wireshark shows the flags of the table: `[SYN]`, `[SYN, ACK]`, `[PSH, ACK]`, `[ACK]`, `[PSH, ACK]`, and `<None>` for packet 6. It shows the TCP payload lengths 0, 0, 10, 0, 100, and 0, and the frame lengths 54, 54, 64, 54, 154, and 54. These agree with the input table.

The expert filter reports 3 lines. Packet 2 has "port numbers reused", and packets 4 and 6 have "duplicate ACK". They come from the order of the probe packets, which is not a real session. They have no effect on the flags or on the payload length. The checksums are valid, and no packet is malformed.

## Verdict

PASS. All 18 expected rule matches are in `matches.jsonl`, and no other pair matches. The `dsize` rules match at the limits 10 and 100 as the description of `N`, `>N`, `<N`, and `N<>M` requires. The `flags` rules separate exact flags, `+`, `!`, and `0`.
