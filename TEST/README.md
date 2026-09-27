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

Add one row per test case when the case passes. Fill the commit column in a later commit, because a commit cannot hold its own hash. A retest adds its commit after the word "retest". The last hash in a row is the commit of the current evidence.

## Folder names

Use the test case ID and a short name: `TC-01_tcp_handshake`, `TC-12_malformed_packet`, `BONUS-01_http_port_8080`.

## Folder contents

| File | Content |
|---|---|
| `README.md` | Purpose, input, command, expected result, actual result, verdict. |
| `input.pcap` | The exact input file. |
| `output.jsonl` | The exact output file. |
| `console.txt` | The console summary of the run. |
