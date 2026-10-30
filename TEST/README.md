# Test evidence

This directory holds the graded evidence. Each assignment has its own folder: `assignment-01/`, `assignment-02/`, and `assignment-03/`. One test case owns one folder in the folder of its assignment.

## Index

| ID | Name | Folder | Command | Result | Commit |
|---|---|---|---|---|---|
| TC-01 | TCP handshake | [`TC-01_tcp_handshake`](assignment-01/TC-01_tcp_handshake/) | `python main.py --pcap TEST/assignment-01/TC-01_tcp_handshake/input.pcap --output TEST/assignment-01/TC-01_tcp_handshake/output.jsonl` | PASS | `bbc1685`, retest `a0872ca`, retest `ff56a0b` |
| TC-02 | TCP data | [`TC-02_tcp_data`](assignment-01/TC-02_tcp_data/) | `python main.py --pcap TEST/assignment-01/TC-02_tcp_data/input.pcap --output TEST/assignment-01/TC-02_tcp_data/output.jsonl` | PASS | `792c8ac`, `d30ca8b`, retest `1daf484`, retest `4644d57` |
| TC-03 | UDP | [`TC-03_udp`](assignment-01/TC-03_udp/) | `python main.py --pcap TEST/assignment-01/TC-03_udp/input.pcap --output TEST/assignment-01/TC-03_udp/output.jsonl` | PASS | `3e5cca7`, retest `50df02b`, retest `7ed1fce` |
| TC-04 | HTTP GET | [`TC-04_http_get`](assignment-01/TC-04_http_get/) | `python main.py --pcap TEST/assignment-01/TC-04_http_get/input.pcap --output TEST/assignment-01/TC-04_http_get/output.jsonl` | PASS | `3a3123b`, retest `61807a0` |
| TC-05 | HTTP POST | [`TC-05_http_post`](assignment-01/TC-05_http_post/) | `python main.py --pcap TEST/assignment-01/TC-05_http_post/input.pcap --output TEST/assignment-01/TC-05_http_post/output.jsonl` | PASS | `c1c93d2`, retest `cd23c91` |
| TC-06 | HTTP response | [`TC-06_http_response`](assignment-01/TC-06_http_response/) | `python main.py --pcap TEST/assignment-01/TC-06_http_response/input.pcap --output TEST/assignment-01/TC-06_http_response/output.jsonl` | PASS | `509da09`, retest `7b2ce4f` |
| TC-07 | DNS query | [`TC-07_dns_query`](assignment-01/TC-07_dns_query/) | `python main.py --pcap TEST/assignment-01/TC-07_dns_query/input.pcap --output TEST/assignment-01/TC-07_dns_query/output.jsonl` | PASS | `bb24e96`, `82a408a`, retest `95ea2dc` |
| TC-08 | DNS response | [`TC-08_dns_response`](assignment-01/TC-08_dns_response/) | `python main.py --pcap TEST/assignment-01/TC-08_dns_response/input.pcap --output TEST/assignment-01/TC-08_dns_response/output.jsonl` | PASS | `402d793`, retest `d831dc7` |
| TC-09 | SMTP command | [`TC-09_smtp_command`](assignment-01/TC-09_smtp_command/) | `python main.py --pcap TEST/assignment-01/TC-09_smtp_command/input.pcap --output TEST/assignment-01/TC-09_smtp_command/output.jsonl` | PASS | `ce42d84`, retest `463df20` |
| TC-10 | SMTP response | [`TC-10_smtp_response`](assignment-01/TC-10_smtp_response/) | `python main.py --pcap TEST/assignment-01/TC-10_smtp_response/input.pcap --output TEST/assignment-01/TC-10_smtp_response/output.jsonl` | PASS | `09ccdfe`, retest `41d6ab0` |
| TC-11 | Unknown protocol | [`TC-11_unknown_protocol`](assignment-01/TC-11_unknown_protocol/) | `python main.py --pcap TEST/assignment-01/TC-11_unknown_protocol/input.pcap --output TEST/assignment-01/TC-11_unknown_protocol/output.jsonl --unknown keep`, then the same with `--unknown drop` and `output_drop.jsonl` | PASS | `a80c754`, retest `055152c` |
| TC-12 | Malformed packet | [`TC-12_malformed_packet`](assignment-01/TC-12_malformed_packet/) | one run per file in `input/`, with `--unknown keep` into `output/` and with `--unknown drop` into `output_drop/` (see the case README) | PASS | `727478e`, retest `4135fd3` |
| BONUS-01 | HTTP on a non-standard port | [`BONUS-01_http_nonstandard_port`](assignment-01/BONUS-01_http_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `b31cf90`, retest `bba9ecd` |
| BONUS-02 | DNS on a non-standard port | [`BONUS-02_dns_nonstandard_port`](assignment-01/BONUS-02_dns_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `02cb171`, retest `bbbb204` |
| BONUS-03 | SMTP on a non-standard port | [`BONUS-03_smtp_nonstandard_port`](assignment-01/BONUS-03_smtp_nonstandard_port/) | `python main.py --pcap TEST/assignment-01/BONUS-03_smtp_nonstandard_port/input.pcap --output TEST/assignment-01/BONUS-03_smtp_nonstandard_port/output.jsonl` | PASS | `334e6c5`, retest `ec5f5e8` |
| BONUS-04 | Detection traps | [`BONUS-04_detection_traps`](assignment-01/BONUS-04_detection_traps/) | `python main.py --pcap TEST/assignment-01/BONUS-04_detection_traps/input.pcap --output TEST/assignment-01/BONUS-04_detection_traps/output.jsonl` | PASS | `c194815`, retest `18a160c` |
| A2-T01 | HTTP URL decode | [`A2-T01_http_url_decode`](assignment-02/A2-T01_http_url_decode/) | `python main.py --pcap TEST/assignment-02/A2-T01_http_url_decode/input.pcap --output TEST/assignment-02/A2-T01_http_url_decode/output.jsonl` | PASS | `6292829` |
| A2-T02 | HTML entity decode | [`A2-T02_html_entity`](assignment-02/A2-T02_html_entity/) | `python main.py --pcap TEST/assignment-02/A2-T02_html_entity/input.pcap --output TEST/assignment-02/A2-T02_html_entity/output.jsonl` | PASS | `3627e33` |
| A2-T03 | SMTP MIME decode | [`A2-T03_smtp_mime`](assignment-02/A2-T03_smtp_mime/) | `python main.py --pcap TEST/assignment-02/A2-T03_smtp_mime/input.pcap --output TEST/assignment-02/A2-T03_smtp_mime/output.jsonl` | PASS | `4a69b2b` |
| A2-T04 | Invalid bytes | [`A2-T04_invalid_bytes`](assignment-02/A2-T04_invalid_bytes/) | `python main.py --pcap TEST/assignment-02/A2-T04_invalid_bytes/input.pcap --output TEST/assignment-02/A2-T04_invalid_bytes/output.jsonl` | PASS | `b474304` |
| A2-T05 | Normalization | [`A2-T05_normalization`](assignment-02/A2-T05_normalization/) | one run per file in `input/` into `output/` (see the case README) | PASS | `b1e8997` |
| A2-T06 | Missing field | [`A2-T06_missing_field`](assignment-02/A2-T06_missing_field/) | `python main.py --events TEST/assignment-02/A2-T06_missing_field/input.jsonl --output TEST/assignment-02/A2-T06_missing_field/output.jsonl` | PASS | `f933dc0` |
| A2-T07 | TCP handshake | [`A2-T07_tcp_handshake`](assignment-02/A2-T07_tcp_handshake/) | `python main.py --pcap TEST/assignment-02/A2-T07_tcp_handshake/input.pcap --output TEST/assignment-02/A2-T07_tcp_handshake/output.jsonl --flows-output TEST/assignment-02/A2-T07_tcp_handshake/flows.jsonl` | PASS | `3568746` |
| A2-T08 | Bidirectional flow | [`A2-T08_bidirectional_flow`](assignment-02/A2-T08_bidirectional_flow/) | `python main.py --pcap TEST/assignment-02/A2-T08_bidirectional_flow/input.pcap --output TEST/assignment-02/A2-T08_bidirectional_flow/output.jsonl --flows-output TEST/assignment-02/A2-T08_bidirectional_flow/flows.jsonl` | PASS | `be64c9b` |
| A2-T09 | TCP close | [`A2-T09_tcp_close`](assignment-02/A2-T09_tcp_close/) | one run per file in `input/` into `output/` and `flows/` (see the case README) | PASS | `e3c1da7` |
| A2-T10 | UDP query and response | [`A2-T10_udp_flow`](assignment-02/A2-T10_udp_flow/) | `python main.py --pcap TEST/assignment-02/A2-T10_udp_flow/input.pcap --output TEST/assignment-02/A2-T10_udp_flow/output.jsonl --flows-output TEST/assignment-02/A2-T10_udp_flow/flows.jsonl` | PASS | `663e3e5` |
| A2-T11 | Concurrent flows | [`A2-T11_concurrent_flows`](assignment-02/A2-T11_concurrent_flows/) | `python main.py --pcap TEST/assignment-02/A2-T11_concurrent_flows/input.pcap --output TEST/assignment-02/A2-T11_concurrent_flows/output.jsonl --flows-output TEST/assignment-02/A2-T11_concurrent_flows/flows.jsonl` | PASS | `91363b8` |
| A2-T12 | Idle timeout | [`A2-T12_idle_timeout`](assignment-02/A2-T12_idle_timeout/) | `python main.py --pcap TEST/assignment-02/A2-T12_idle_timeout/input.pcap --output TEST/assignment-02/A2-T12_idle_timeout/output.jsonl --flows-output TEST/assignment-02/A2-T12_idle_timeout/flows.jsonl` | PASS | `90b838d` |
| A2-T13 | Flow statistics | [`A2-T13_flow_statistics`](assignment-02/A2-T13_flow_statistics/) | `python main.py --pcap TEST/assignment-02/A2-T13_flow_statistics/input.pcap --output TEST/assignment-02/A2-T13_flow_statistics/output.jsonl --flows-output TEST/assignment-02/A2-T13_flow_statistics/flows.jsonl` | PASS | `8bd2ef5` |
| A2-T14 | Malformed event | [`A2-T14_malformed_event`](assignment-02/A2-T14_malformed_event/) | one run per file in `input/`, with `--unknown keep` into `output/` and with `--unknown drop` into `output_drop/` (see the case README) | PASS | `4aba51f` |
| A3-T01 | Rule file with comments | [`A3-T01_rule_file_comments`](assignment-03/A3-T01_rule_file_comments/) | `python main.py --pcap TEST/assignment-03/A3-T01_rule_file_comments/input/traffic.pcap --rules-config TEST/assignment-03/A3-T01_rule_file_comments/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T02 | Invalid rule | [`A3-T02_invalid_rule`](assignment-03/A3-T02_invalid_rule/) | `python main.py --pcap TEST/assignment-03/A3-T02_invalid_rule/input/traffic.pcap --rules-config TEST/assignment-03/A3-T02_invalid_rule/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T03 | Unsupported keyword | [`A3-T03_unsupported_keyword`](assignment-03/A3-T03_unsupported_keyword/) | `python main.py --pcap TEST/assignment-03/A3-T03_unsupported_keyword/input/traffic.pcap --rules-config TEST/assignment-03/A3-T03_unsupported_keyword/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T04 | Rule header parsing | [`A3-T04_rule_header`](assignment-03/A3-T04_rule_header/) | `python main.py --pcap TEST/assignment-03/A3-T04_rule_header/input/traffic.pcap --rules-config TEST/assignment-03/A3-T04_rule_header/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T05 | Rule direction | [`A3-T05_direction`](assignment-03/A3-T05_direction/) | `python main.py --pcap TEST/assignment-03/A3-T05_direction/input/traffic.pcap --rules-config TEST/assignment-03/A3-T05_direction/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T06 | Rule index | [`A3-T06_rule_index`](assignment-03/A3-T06_rule_index/) | `python main.py --pcap TEST/assignment-03/A3-T06_rule_index/input/traffic.pcap --rules-config TEST/assignment-03/A3-T06_rule_index/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T07 | Header mismatch | [`A3-T07_header_mismatch`](assignment-03/A3-T07_header_mismatch/) | `python main.py --pcap TEST/assignment-03/A3-T07_header_mismatch/input/traffic.pcap --rules-config TEST/assignment-03/A3-T07_header_mismatch/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T08 | Flow to_server, established | [`A3-T08_flow_established`](assignment-03/A3-T08_flow_established/) | `python main.py --pcap TEST/assignment-03/A3-T08_flow_established/input/traffic.pcap --rules-config TEST/assignment-03/A3-T08_flow_established/input/rules.toml`, with the four output options (see the case README) | PASS |  |
| A3-T09 | Content nocase | [`A3-T09_content_nocase`](assignment-03/A3-T09_content_nocase/) | `python main.py --pcap TEST/assignment-03/A3-T09_content_nocase/input/traffic.pcap --rules-config TEST/assignment-03/A3-T09_content_nocase/input/rules.toml`, with the four output options (see the case README) | PASS |  |

Add one row per test case when the case passes. Fill the commit column in a later commit, because a commit cannot hold its own hash. A retest adds its commit after the word "retest". The last hash in a row is the commit of the current evidence.

## Folder names

Use the test case ID and a short name: `TC-01_tcp_handshake`, `TC-12_malformed_packet`, `BONUS-01_http_port_8080`, `A2-T07_tcp_handshake`. Put the case folder in the folder of its assignment, for example `assignment-02/A2-T07_tcp_handshake`.

## Console summary format

`console.txt` shows the summary of the program at the last commit of the folder. Every folder now holds the summary of Assignment 02: it counts the parse statuses (`ok`, `partial`, `unsupported`, `malformed`, `other`), the preprocess statuses, the dropped events, and the flow records. The script `tests/check_evidence_compat.py` guards every folder: it reruns each input and compares the base fields of the output files with the committed ones. It does not check `console.txt`.

## Folder contents

| File | Content |
|---|---|
| `README.md` | Purpose, input, command, expected result, actual result, verdict. |
| `input.pcap` or `input.jsonl` | The exact input file: a PCAP file, or an events file. |
| `input/` | Instead of one input file: a folder with several input files, one per run. |
| `output.jsonl` | The exact output file. |
| `output_drop.jsonl` | The output of the run with `--unknown drop`, when the case has one. |
| `output/`, `output_drop/` | Instead of one output file: one output file per input file, for `--unknown keep` and for `--unknown drop`. |
| `flows.jsonl` or `flows/` | The flow records of the run, in the cases that check flows. |
| `console.txt` | The console summary of the run. |

An Assignment 03 case holds `input/` (the pcap, the `.rules` file, and `rules.toml`) and `output/` (`events.jsonl`, `flows.jsonl`, `matches.jsonl`, `rules_report.jsonl`). `matches.jsonl` holds the rule matches, and `rules_report.jsonl` holds one line for each rule line. `console.txt` also holds the command and the exit code.
