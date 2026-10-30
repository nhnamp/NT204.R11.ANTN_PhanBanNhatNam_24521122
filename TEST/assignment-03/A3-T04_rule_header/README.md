# A3-T04 — Rule header parsing

## Purpose

The parser must turn each header form into the right internal rule object. The forms are `any`, a single IP, a CIDR, a single port, a port range `a:b`, and the open ranges `a:` and `:b`. This is test case 4 of the description. The matches show that the engine also uses the objects correctly.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t04_rule_header/`.

`traffic.pcap` (1 packet):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (`GET /index.html HTTP/1.1`, a `Host` header) | 101 |

`local.rules` holds 7 rules on lines 2 to 8. Each rule has `content:"GET "; depth:4`, which the payload holds. Only the header differs.

| Line | Sid | Header | Form |
|---|---|---|---|
| 2 | 100401 | `tcp any any -> any any` | `any` |
| 3 | 100402 | `tcp 10.0.0.1 any -> 10.0.0.2 any` | single IP |
| 4 | 100403 | `tcp 10.0.0.0/24 any -> 192.168.0.0/16 any` | CIDR |
| 5 | 100404 | `tcp any any -> any 80` | single port |
| 6 | 100405 | `tcp any any -> any 8000:8100` | range `a:b` |
| 7 | 100406 | `tcp any 1024: -> any any` | open range `a:` |
| 8 | 100407 | `tcp any :1023 -> any any` | open range `:b` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T04_rule_header/input/traffic.pcap --rules-config TEST/assignment-03/A3-T04_rule_header/input/rules.toml --output TEST/assignment-03/A3-T04_rule_header/output/events.jsonl --flows-output TEST/assignment-03/A3-T04_rule_header/output/flows.jsonl --matches-output TEST/assignment-03/A3-T04_rule_header/output/matches.jsonl --rules-report TEST/assignment-03/A3-T04_rule_header/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0. All 7 rules are `valid`.
- In the internal object, `any` is `null`. A single IP is a network with prefix `/32`. A CIDR keeps its prefix. A single port has `low` equal to `high`. A range has `low` and `high`. The open range `a:` has `high=65535`. The open range `:b` has `low=0`.
- All 7 rules are candidates for the TCP record: `candidate rules: 7`.
- The packet is 10.0.0.1:40000 → 10.0.0.2:80. These rules match: 100401 (`any`), 100402 (both IPs), 100404 (destination port 80), 100406 (source port 40000 is in 1024 to 65535).
- These rules fail on the header: 100403 (destination is not in 192.168.0.0/16), 100405 (port 80 is not in 8000 to 8100), 100407 (source port 40000 is not in 0 to 1023). So `rejected by header: 3`, `rejected by content: 0`, and `rule matches: 4`.

## Actual result

The header part of the internal object of each rule, from `rules_report.jsonl`:

| Sid | `src_ip` | `src_port` | `dst_ip` | `dst_port` |
|---|---|---|---|---|
| 100401 | `null` | `null` | `null` | `null` |
| 100402 | `10.0.0.1/32` | `null` | `10.0.0.2/32` | `null` |
| 100403 | `10.0.0.0/24` | `null` | `192.168.0.0/16` | `null` |
| 100404 | `null` | `null` | `null` | `{"low": 80, "high": 80}` |
| 100405 | `null` | `null` | `null` | `{"low": 8000, "high": 8100}` |
| 100406 | `null` | `{"low": 1024, "high": 65535}` | `null` | `null` |
| 100407 | `null` | `{"low": 0, "high": 1023}` | `null` | `null` |

All rules have `protocol="tcp"` and `direction="->"`. The summary shows `candidate rules: 7`, `rejected by header: 3`, `rejected by content: 0`, `rule matches: 4`, `engine errors: 0`. The exit code is 0. `matches.jsonl` holds the sids 100401, 100402, 100404, and 100406.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      0 0 bytes         1 101 bytes       1 101 bytes     0.000000000         0.0000
```

Wireshark shows source 10.0.0.1 port 40000 and destination 10.0.0.2 port 80. These values give the match results above: the addresses are in the single IP rule and in 10.0.0.0/24, the destination is not in 192.168.0.0/16, port 80 is outside 8000 to 8100, and port 40000 is inside 1024 to 65535 and outside 0 to 1023. The expert and malformed filter finds no problem.

## Verdict

PASS. Each header form gives the expected internal object. The 4 rules whose header fits the packet match, and the 3 other rules fail on the header.
