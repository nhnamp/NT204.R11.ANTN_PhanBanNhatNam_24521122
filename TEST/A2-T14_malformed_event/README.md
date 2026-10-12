# A2-T14 — Malformed event

## Purpose

An invalid or unsupported event must not stop the run. The status and the reason must fit the fault (`PRE-2`, `PRE-4`, `PRE-5`). The policy `--unknown drop` must remove the invalid and unsupported events and must count them in the summary.

## Input

This case uses a folder, because it has two kinds of input: a PCAP file and an events file.

`input/unknown_protocols.pcap` is a copy of `tests/fixtures/unknown_protocols.pcap`. It holds five packets from `10.0.0.1` to `10.0.0.2`, except for packets 1 and 2.

| Packet | Frame length (bytes) | Content |
|---|---|---|
| 1 | 74 | IPv6 TCP SYN, `2001:db8::1` to `2001:db8::2`, port 80 |
| 2 | 42 | ARP request, who has `10.0.0.2` |
| 3 | 46 | ICMP echo request |
| 4 | 78 | GRE packet, with an inner TCP SYN from `10.0.0.3` to `10.0.0.4` |
| 5 | 118 | TCP, port 4444, 64 random bytes |

`input/invalid_events.jsonl` is a copy of `tests/fixtures/events/invalid_events.jsonl`. It holds 8 lines.

| Line | Content |
|---|---|
| 1 | `{}` |
| 2 | `[]` |
| 3 | `"text"` |
| 4 | `{not json` |
| 5 | A TCP event with the destination port 70 000 |
| 6 | A TCP event with the timestamp `true` |
| 7 | A TCP event with the timestamp `"9999-12-31T23:59:59"` (outside the range of 0 to 4 102 444 800) |
| 8 | An event with `network` and `transport` as `null` and `status` `unsupported` |

## Commands

Run the commands from the repository root. The first two use the policy `keep`. The last two use `drop`. Each run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

```bash
python main.py --pcap TEST/A2-T14_malformed_event/input/unknown_protocols.pcap --output TEST/A2-T14_malformed_event/output/unknown_protocols.jsonl --unknown keep
```

```bash
python main.py --events TEST/A2-T14_malformed_event/input/invalid_events.jsonl --output TEST/A2-T14_malformed_event/output/invalid_events.jsonl --unknown keep
```

```bash
python main.py --pcap TEST/A2-T14_malformed_event/input/unknown_protocols.pcap --output TEST/A2-T14_malformed_event/output_drop/unknown_protocols.jsonl --unknown drop
```

```bash
python main.py --events TEST/A2-T14_malformed_event/input/invalid_events.jsonl --output TEST/A2-T14_malformed_event/output_drop/invalid_events.jsonl --unknown drop
```

## Expected result

The expected values follow from the validation rules of the plan (R4.2 and R4.4). All 4 runs exit with code 0 and show no traceback.

**PCAP file.** The IDS supports IPv4 with TCP or UDP. Every other packet is `unsupported`, and the Preprocessor marks it `partial` with `skip_flow`.

| Packet | `status` | `preprocess_status` | `processing_action` | `reason` |
|---|---|---|---|---|
| 1 (IPv6) | `unsupported` | `partial` | `skip_flow` | `no network layer; no transport layer` |
| 2 (ARP) | `unsupported` | `partial` | `skip_flow` | `no network layer; no transport layer` |
| 3 (ICMP) | `unsupported` | `partial` | `skip_flow` | `no transport layer` |
| 4 (GRE) | `unsupported` | `partial` | `skip_flow` | `no transport layer` |
| 5 (TCP port 4444) | `ok` | `valid` | `keep` | `null` |

**Events file.**

| Line | `preprocess_status` | `processing_action` | `reason` | Other |
|---|---|---|---|---|
| 1 | `invalid` | `skip_flow` | `timestamp is missing or unusable` | |
| 2, 3, 4 | `invalid` | `skip_flow` | `input line is not a usable event` | one `processing_errors` entry of type `invalid_record` |
| 5 | `partial` | `skip_flow` | `port is missing or out of range` | |
| 6 | `invalid` | `skip_flow` | `timestamp is missing or unusable` | |
| 7 | `invalid` | `skip_flow` | `timestamp is missing or unusable` | |
| 8 | `partial` | `skip_flow` | `no network layer; no transport layer` | `status` stays `unsupported` |

**Policy `keep`.** Every packet and every line gives one event: 5 events from the PCAP file and 8 from the events file.

**Policy `drop`.** The policy removes the `unsupported` events and the `invalid` events. It keeps a `partial` event that is not `unsupported`.
- From the PCAP file, 4 events go (packets 1 to 4). Packet 5 stays.
- From the events file, 7 events go (lines 1 to 4, 6, 7, and 8). Line 5 stays.
- The summary counts the removed events under `dropped`: 4 and 7.

## Actual result

`output/` holds the events of the `keep` runs, and `output_drop/` holds the events of the `drop` runs. `console.txt` holds the 4 commands, their summaries, and the exit codes. All 4 exit codes are 0. The values equal the Expected result.

| Run | Events written | Dropped | `preprocess` valid / partial / invalid |
|---|---|---|---|
| PCAP file, `keep` | 5 | 0 | 1 / 4 / 0 |
| Events file, `keep` | 8 | 0 | 0 / 2 / 6 |
| PCAP file, `drop` | 1 | 4 | 1 / 0 / 0 |
| Events file, `drop` | 1 | 7 | 0 / 1 / 0 |

Notes:
- The event of packet 5 has a decoded item `payload` with the reason `binary payload`, because the payload is random. Its `flow_id` is `tcp-754b9f097b1c`.
- The events of lines 2, 3, and 4 have only a `source` (for example `events:TEST/A2-T14_malformed_event/input/invalid_events.jsonl:2`) and the enrichment fields. The `processing_errors` message of line 4 starts with `line is not valid JSON` and names the position of the fault.
- The IDS reads only IPv4 packets. Packet 1 is IPv6, so its `network` is `null`, although Wireshark decodes it. The IDS does not read the inner packet of the GRE tunnel in packet 4. Its `network` shows only the outer IPv4 header, and `transport` is `null`.

## Wireshark check

The packets of `unknown_protocols.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The events file is not a capture file, so it has no Wireshark part.

The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison.

| Packet | Wireshark protocol and Info | Wireshark length | `length` of the event | `payload_len` of the event | Match |
|---|---|---|---|---|---|
| 1 | TCP over IPv6, 2001:db8::1 → 2001:db8::2, port 40000 to port 80, SYN | 74 | 74 | 0 | yes |
| 2 | ARP, who has 10.0.0.2? Tell 10.0.0.1 | 42 | 42 | 0 | yes |
| 3 | ICMP, echo (ping) request | 46 | 46 | 0 | yes |
| 4 | TCP, port 40000 to port 80, SYN, IP protocol 47 (GRE) around IP protocol 6 (TCP) | 78 | 78 | 0 | yes |
| 5 | TCP, port 40000 to port 4444, PSH and ACK, payload 64 bytes | 118 | 118 | 64 | yes |

The 64 payload bytes of packet 5 equal `payload_hex` of the event. For packets 1 to 4, the IDS reads no payload, because it supports no transport layer there. Wireshark shows the layer that the IDS does not read (IPv6, ARP, ICMP, the inner TCP of the GRE tunnel). This difference is the reason for the status `unsupported`.

## Verdict

PASS. No invalid or unsupported input stops the run. Each fault gets a `preprocess_status` and a `reason` that name its cause. The policy `drop` removes the invalid and unsupported events and counts them under `dropped`. The packets and the payload bytes equal the Wireshark values.
