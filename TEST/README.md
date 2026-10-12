# Test evidence

This directory holds the graded evidence for Assignments 01 and 02. One test case owns one folder.

## Index

| ID | Name | Folder | Command | Result | Commit |
|---|---|---|---|---|---|
| TC-01 | TCP handshake | [`TC-01_tcp_handshake`](TC-01_tcp_handshake/) | `python main.py --pcap TEST/TC-01_tcp_handshake/input.pcap --output TEST/TC-01_tcp_handshake/output.jsonl` | PASS | `bbc1685`, retest `a0872ca`, retest `ff56a0b` |
| TC-02 | TCP data | [`TC-02_tcp_data`](TC-02_tcp_data/) | `python main.py --pcap TEST/TC-02_tcp_data/input.pcap --output TEST/TC-02_tcp_data/output.jsonl` | PASS | `792c8ac`, `d30ca8b`, retest `1daf484`, retest `4644d57` |
| TC-03 | UDP | [`TC-03_udp`](TC-03_udp/) | `python main.py --pcap TEST/TC-03_udp/input.pcap --output TEST/TC-03_udp/output.jsonl` | PASS | `3e5cca7`, retest `50df02b`, retest `7ed1fce` |
| TC-04 | HTTP GET | [`TC-04_http_get`](TC-04_http_get/) | `python main.py --pcap TEST/TC-04_http_get/input.pcap --output TEST/TC-04_http_get/output.jsonl` | PASS | `3a3123b`, retest `61807a0` |
| TC-05 | HTTP POST | [`TC-05_http_post`](TC-05_http_post/) | `python main.py --pcap TEST/TC-05_http_post/input.pcap --output TEST/TC-05_http_post/output.jsonl` | PASS | `c1c93d2`, retest `cd23c91` |
| TC-06 | HTTP response | [`TC-06_http_response`](TC-06_http_response/) | `python main.py --pcap TEST/TC-06_http_response/input.pcap --output TEST/TC-06_http_response/output.jsonl` | PASS | `509da09`, retest `7b2ce4f` |
| TC-07 | DNS query | [`TC-07_dns_query`](TC-07_dns_query/) | `python main.py --pcap TEST/TC-07_dns_query/input.pcap --output TEST/TC-07_dns_query/output.jsonl` | PASS | `bb24e96`, `82a408a`, retest `95ea2dc` |
| TC-08 | DNS response | [`TC-08_dns_response`](TC-08_dns_response/) | `python main.py --pcap TEST/TC-08_dns_response/input.pcap --output TEST/TC-08_dns_response/output.jsonl` | PASS | `402d793`, retest `d831dc7` |
| TC-09 | SMTP command | [`TC-09_smtp_command`](TC-09_smtp_command/) | `python main.py --pcap TEST/TC-09_smtp_command/input.pcap --output TEST/TC-09_smtp_command/output.jsonl` | PASS | `ce42d84`, retest `463df20` |
| TC-10 | SMTP response | [`TC-10_smtp_response`](TC-10_smtp_response/) | `python main.py --pcap TEST/TC-10_smtp_response/input.pcap --output TEST/TC-10_smtp_response/output.jsonl` | PASS | `09ccdfe`, retest `41d6ab0` |
| TC-11 | Unknown protocol | [`TC-11_unknown_protocol`](TC-11_unknown_protocol/) | `python main.py --pcap TEST/TC-11_unknown_protocol/input.pcap --output TEST/TC-11_unknown_protocol/output.jsonl --unknown keep`, then the same with `--unknown drop` and `output_drop.jsonl` | PASS | `a80c754`, retest `055152c` |
| TC-12 | Malformed packet | [`TC-12_malformed_packet`](TC-12_malformed_packet/) | one run per file in `input/`, with `--unknown keep` into `output/` and with `--unknown drop` into `output_drop/` (see the case README) | PASS | `727478e`, retest `4135fd3` |
| BONUS-01 | HTTP on a non-standard port | [`BONUS-01_http_nonstandard_port`](BONUS-01_http_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `b31cf90`, retest `bba9ecd` |
| BONUS-02 | DNS on a non-standard port | [`BONUS-02_dns_nonstandard_port`](BONUS-02_dns_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `02cb171`, retest `bbbb204` |
| BONUS-03 | SMTP on a non-standard port | [`BONUS-03_smtp_nonstandard_port`](BONUS-03_smtp_nonstandard_port/) | `python main.py --pcap TEST/BONUS-03_smtp_nonstandard_port/input.pcap --output TEST/BONUS-03_smtp_nonstandard_port/output.jsonl` | PASS | `334e6c5`, retest `ec5f5e8` |
| BONUS-04 | Detection traps | [`BONUS-04_detection_traps`](BONUS-04_detection_traps/) | `python main.py --pcap TEST/BONUS-04_detection_traps/input.pcap --output TEST/BONUS-04_detection_traps/output.jsonl` | PASS | `c194815`, retest `18a160c` |
| A2-T01 | HTTP URL decode | [`A2-T01_http_url_decode`](A2-T01_http_url_decode/) | `python main.py --pcap TEST/A2-T01_http_url_decode/input.pcap --output TEST/A2-T01_http_url_decode/output.jsonl` | PASS | `6292829` |
| A2-T02 | HTML entity decode | [`A2-T02_html_entity`](A2-T02_html_entity/) | `python main.py --pcap TEST/A2-T02_html_entity/input.pcap --output TEST/A2-T02_html_entity/output.jsonl` | PASS | `3627e33` |
| A2-T03 | SMTP MIME decode | [`A2-T03_smtp_mime`](A2-T03_smtp_mime/) | `python main.py --pcap TEST/A2-T03_smtp_mime/input.pcap --output TEST/A2-T03_smtp_mime/output.jsonl` | PASS | `4a69b2b` |
| A2-T04 | Invalid bytes | [`A2-T04_invalid_bytes`](A2-T04_invalid_bytes/) | `python main.py --pcap TEST/A2-T04_invalid_bytes/input.pcap --output TEST/A2-T04_invalid_bytes/output.jsonl` | PASS | `b474304` |
| A2-T05 | Normalization | [`A2-T05_normalization`](A2-T05_normalization/) | one run per file in `input/` into `output/` (see the case README) | PASS | `b1e8997` |
| A2-T06 | Missing field | [`A2-T06_missing_field`](A2-T06_missing_field/) | `python main.py --events TEST/A2-T06_missing_field/input.jsonl --output TEST/A2-T06_missing_field/output.jsonl` | PASS | `f933dc0` |
| A2-T07 | TCP handshake | [`A2-T07_tcp_handshake`](A2-T07_tcp_handshake/) | `python main.py --pcap TEST/A2-T07_tcp_handshake/input.pcap --output TEST/A2-T07_tcp_handshake/output.jsonl --flows-output TEST/A2-T07_tcp_handshake/flows.jsonl` | PASS | `3568746` |
| A2-T08 | Bidirectional flow | [`A2-T08_bidirectional_flow`](A2-T08_bidirectional_flow/) | `python main.py --pcap TEST/A2-T08_bidirectional_flow/input.pcap --output TEST/A2-T08_bidirectional_flow/output.jsonl --flows-output TEST/A2-T08_bidirectional_flow/flows.jsonl` | PASS | `be64c9b` |
| A2-T09 | TCP close | [`A2-T09_tcp_close`](A2-T09_tcp_close/) | one run per file in `input/` into `output/` and `flows/` (see the case README) | PASS | `e3c1da7` |
| A2-T10 | UDP query and response | [`A2-T10_udp_flow`](A2-T10_udp_flow/) | `python main.py --pcap TEST/A2-T10_udp_flow/input.pcap --output TEST/A2-T10_udp_flow/output.jsonl --flows-output TEST/A2-T10_udp_flow/flows.jsonl` | PASS | `663e3e5` |
| A2-T11 | Concurrent flows | [`A2-T11_concurrent_flows`](A2-T11_concurrent_flows/) | `python main.py --pcap TEST/A2-T11_concurrent_flows/input.pcap --output TEST/A2-T11_concurrent_flows/output.jsonl --flows-output TEST/A2-T11_concurrent_flows/flows.jsonl` | PASS | `91363b8` |
| A2-T12 | Idle timeout | [`A2-T12_idle_timeout`](A2-T12_idle_timeout/) | `python main.py --pcap TEST/A2-T12_idle_timeout/input.pcap --output TEST/A2-T12_idle_timeout/output.jsonl --flows-output TEST/A2-T12_idle_timeout/flows.jsonl` | PASS | `90b838d` |
| A2-T13 | Flow statistics | [`A2-T13_flow_statistics`](A2-T13_flow_statistics/) | `python main.py --pcap TEST/A2-T13_flow_statistics/input.pcap --output TEST/A2-T13_flow_statistics/output.jsonl --flows-output TEST/A2-T13_flow_statistics/flows.jsonl` | PASS | `8bd2ef5` |
| A2-T14 | Malformed event | [`A2-T14_malformed_event`](A2-T14_malformed_event/) | one run per file in `input/`, with `--unknown keep` into `output/` and with `--unknown drop` into `output_drop/` (see the case README) | PASS | `4aba51f` |

Add one row per test case when the case passes. Fill the commit column in a later commit, because a commit cannot hold its own hash. A retest adds its commit after the word "retest". The last hash in a row is the commit of the current evidence.

## Folder names

Use the test case ID and a short name: `TC-01_tcp_handshake`, `TC-12_malformed_packet`, `BONUS-01_http_port_8080`, `A2-T07_tcp_handshake`.

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
