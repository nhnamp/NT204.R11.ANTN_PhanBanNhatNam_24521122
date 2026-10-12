# Test evidence

This directory holds the graded evidence for Assignment 01. One test case owns one folder.

## Index

| ID | Name | Folder | Command | Result | Commit |
|---|---|---|---|---|---|
| TC-01 | TCP handshake | [`TC-01_tcp_handshake`](TC-01_tcp_handshake/) | `python main.py --pcap TEST/TC-01_tcp_handshake/input.pcap --output TEST/TC-01_tcp_handshake/output.jsonl` | PASS | `bbc1685`, retest `a0872ca` |
| TC-02 | TCP data | [`TC-02_tcp_data`](TC-02_tcp_data/) | `python main.py --pcap TEST/TC-02_tcp_data/input.pcap --output TEST/TC-02_tcp_data/output.jsonl` | PASS | `792c8ac`, `d30ca8b`, retest `1daf484` |
| TC-03 | UDP | [`TC-03_udp`](TC-03_udp/) | `python main.py --pcap TEST/TC-03_udp/input.pcap --output TEST/TC-03_udp/output.jsonl` | PASS | `3e5cca7`, retest `50df02b` |
| TC-04 | HTTP GET | [`TC-04_http_get`](TC-04_http_get/) | `python main.py --pcap TEST/TC-04_http_get/input.pcap --output TEST/TC-04_http_get/output.jsonl` | PASS | `3a3123b` |
| TC-05 | HTTP POST | [`TC-05_http_post`](TC-05_http_post/) | `python main.py --pcap TEST/TC-05_http_post/input.pcap --output TEST/TC-05_http_post/output.jsonl` | PASS | `c1c93d2` |
| TC-06 | HTTP response | [`TC-06_http_response`](TC-06_http_response/) | `python main.py --pcap TEST/TC-06_http_response/input.pcap --output TEST/TC-06_http_response/output.jsonl` | PASS | `509da09` |
| TC-07 | DNS query | [`TC-07_dns_query`](TC-07_dns_query/) | `python main.py --pcap TEST/TC-07_dns_query/input.pcap --output TEST/TC-07_dns_query/output.jsonl` | PASS | `bb24e96`, `82a408a` |
| TC-08 | DNS response | [`TC-08_dns_response`](TC-08_dns_response/) | `python main.py --pcap TEST/TC-08_dns_response/input.pcap --output TEST/TC-08_dns_response/output.jsonl` | PASS | `402d793` |
| TC-09 | SMTP command | [`TC-09_smtp_command`](TC-09_smtp_command/) | `python main.py --pcap TEST/TC-09_smtp_command/input.pcap --output TEST/TC-09_smtp_command/output.jsonl` | PASS | `ce42d84` |
| TC-10 | SMTP response | [`TC-10_smtp_response`](TC-10_smtp_response/) | `python main.py --pcap TEST/TC-10_smtp_response/input.pcap --output TEST/TC-10_smtp_response/output.jsonl` | PASS | `09ccdfe` |
| TC-11 | Unknown protocol | [`TC-11_unknown_protocol`](TC-11_unknown_protocol/) | `python main.py --pcap TEST/TC-11_unknown_protocol/input.pcap --output TEST/TC-11_unknown_protocol/output.jsonl --unknown keep`, then the same with `--unknown drop` and `output_drop.jsonl` | PASS | `a80c754` |
| TC-12 | Malformed packet | [`TC-12_malformed_packet`](TC-12_malformed_packet/) | one run per file in `input/`, with `--unknown keep` into `output/` and with `--unknown drop` into `output_drop/` (see the case README) | PASS | `727478e` |
| BONUS-01 | HTTP on a non-standard port | [`BONUS-01_http_nonstandard_port`](BONUS-01_http_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `b31cf90` |
| BONUS-02 | DNS on a non-standard port | [`BONUS-02_dns_nonstandard_port`](BONUS-02_dns_nonstandard_port/) | one run per file in `input/` into `output/` (see the case README) | PASS | `02cb171` |
| BONUS-03 | SMTP on a non-standard port | [`BONUS-03_smtp_nonstandard_port`](BONUS-03_smtp_nonstandard_port/) | `python main.py --pcap TEST/BONUS-03_smtp_nonstandard_port/input.pcap --output TEST/BONUS-03_smtp_nonstandard_port/output.jsonl` | PASS | `334e6c5` |
| BONUS-04 | Detection traps | [`BONUS-04_detection_traps`](BONUS-04_detection_traps/) | `python main.py --pcap TEST/BONUS-04_detection_traps/input.pcap --output TEST/BONUS-04_detection_traps/output.jsonl` | PASS | `c194815` |
| A2-T07 | TCP handshake | [`A2-T07_tcp_handshake`](A2-T07_tcp_handshake/) | `python main.py --pcap TEST/A2-T07_tcp_handshake/input.pcap --output TEST/A2-T07_tcp_handshake/output.jsonl --flows-output TEST/A2-T07_tcp_handshake/flows.jsonl` | PASS | |
| A2-T08 | Bidirectional flow | [`A2-T08_bidirectional_flow`](A2-T08_bidirectional_flow/) | `python main.py --pcap TEST/A2-T08_bidirectional_flow/input.pcap --output TEST/A2-T08_bidirectional_flow/output.jsonl --flows-output TEST/A2-T08_bidirectional_flow/flows.jsonl` | PASS | |
| A2-T09 | TCP close | [`A2-T09_tcp_close`](A2-T09_tcp_close/) | one run per file in `input/` into `output/` and `flows/` (see the case README) | PASS | |
| A2-T10 | UDP query and response | [`A2-T10_udp_flow`](A2-T10_udp_flow/) | `python main.py --pcap TEST/A2-T10_udp_flow/input.pcap --output TEST/A2-T10_udp_flow/output.jsonl --flows-output TEST/A2-T10_udp_flow/flows.jsonl` | PASS | |
| A2-T11 | Concurrent flows | [`A2-T11_concurrent_flows`](A2-T11_concurrent_flows/) | `python main.py --pcap TEST/A2-T11_concurrent_flows/input.pcap --output TEST/A2-T11_concurrent_flows/output.jsonl --flows-output TEST/A2-T11_concurrent_flows/flows.jsonl` | PASS | |
| A2-T12 | Idle timeout | [`A2-T12_idle_timeout`](A2-T12_idle_timeout/) | `python main.py --pcap TEST/A2-T12_idle_timeout/input.pcap --output TEST/A2-T12_idle_timeout/output.jsonl --flows-output TEST/A2-T12_idle_timeout/flows.jsonl` | PASS | |
| A2-T13 | Flow statistics | [`A2-T13_flow_statistics`](A2-T13_flow_statistics/) | `python main.py --pcap TEST/A2-T13_flow_statistics/input.pcap --output TEST/A2-T13_flow_statistics/output.jsonl --flows-output TEST/A2-T13_flow_statistics/flows.jsonl` | PASS | |

Add one row per test case when the case passes. Fill the commit column in a later commit, because a commit cannot hold its own hash. A retest adds its commit after the word "retest". The last hash in a row is the commit of the current evidence.

## Folder names

Use the test case ID and a short name: `TC-01_tcp_handshake`, `TC-12_malformed_packet`, `BONUS-01_http_port_8080`.

## Console summary format

`console.txt` shows the summary format of the phase that produced it. From P9 on, the summary counts every status: `ok`, `partial`, `unsupported`, and `malformed`. An earlier `console.txt` shows fewer lines. The comparison in R11.3 checks `output.jsonl` only.

## Folder contents

| File | Content |
|---|---|
| `README.md` | Purpose, input, command, expected result, actual result, verdict. |
| `input.pcap` | The exact input file. |
| `output.jsonl` | The exact output file. |
| `console.txt` | The console summary of the run. |
