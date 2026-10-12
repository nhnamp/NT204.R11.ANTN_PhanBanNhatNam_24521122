# TC-12 — Malformed packet

## Purpose

The program must not crash on a malformed packet (`ERR-1`). It must not stop on a missing header, an empty payload, a truncated PCAP record, or a payload that it cannot decode. Every fault must be visible in the output.

## Input

`input/` is a copy of the bad-input corpus in `tests/fixtures/malformed/` (R9.2). The script `tests/fixtures/build_pcaps.py` generates it. The corpus has 21 files for 20 items: item 20 has one file per unusual link type.

Most items are one valid frame with one field changed on purpose. A crafted PCAP header is written byte by byte, because Scapy corrects every length field when it builds a packet.

This case uses a folder instead of one `input.pcap`, because the items cannot share one file:

- Item 18 is a PCAP file whose last record is cut.
- Item 19 is not a PCAP file.
- Item 20 uses the link types NULL and LINUX_SLL, and one PCAP file has one link type.

## Commands

Run the commands from the repository root. The first loop uses the default policy, `keep`. The second loop uses `drop`.

```bash
for f in TEST/TC-12_malformed_packet/input/*; do n=$(basename "$f"); python main.py --pcap "$f" --output "TEST/TC-12_malformed_packet/output/${n%.*}.jsonl" --unknown keep; done
```

```bash
for f in TEST/TC-12_malformed_packet/input/*; do n=$(basename "$f"); python main.py --pcap "$f" --output "TEST/TC-12_malformed_packet/output_drop/${n%.*}.jsonl" --unknown drop; done
```

## Expected result

- All 42 runs (21 files × 2 policies) exit with code 0. No traceback appears.
- Every packet becomes an event, and every corpus item shows its fault in `errors[].type`, `status`, or `detection.method`.
- A malformed network header keeps the IPv4 addresses in `network`.
- `--unknown drop` removes only the events with `status="unsupported"`. Every `malformed` and `partial` event stays.

## Actual result

`output/` holds the events of the `keep` runs, and `output_drop/` holds the events of the `drop` runs. `console.txt` holds all 42 commands, their summaries, and their exit codes. All 42 exit codes are 0.

| Item | Fault | `status` | `app_protocol` / `detection.method` | `errors` (`stage`/`type`) | Kept by `drop` |
|---|---|---|---|---|---|
| 01 | IPv4 IHL = 3 | `malformed` | `UNKNOWN` / `none` | `network`/`malformed` | yes |
| 02 | IPv4 total length larger than the frame | `partial` | `UNKNOWN` / `none` | `transport`/`truncated` | yes |
| 03 | IPv4 total length smaller than the header | `malformed` | `UNKNOWN` / `none` | `network`/`malformed` | yes |
| 04 | TCP data offset = 2 | `malformed` | `UNKNOWN` / `none` | `transport`/`malformed` | yes |
| 05 | TCP header cut after 8 bytes | `malformed` | `UNKNOWN` / `none` | `transport`/`truncated` | yes |
| 06 | UDP length larger than the datagram | `partial` | `UNKNOWN` / `none` | `transport`/`truncated` | yes |
| 07 | UDP length smaller than 8 | `malformed` | `UNKNOWN` / `none` | `transport`/`malformed` | yes |
| 08 | DNS answer name with a pointer loop | `malformed` | `DNS` / `port+payload` | `dns`/`malformed` | yes |
| 09 | DNS `QDCOUNT=65535` in 12 bytes | `ok` | `UNKNOWN` / `none` | none | yes |
| 10 | DNS answer label length 100 | `malformed` | `DNS` / `port+payload` | `dns`/`malformed` | yes |
| 11 | HTTP request line of 20 KB without CRLF | `partial` | `HTTP` / `port+payload` | `http`/`limit` | yes |
| 12 | HTTP request with 300 header lines | `partial` | `HTTP` / `port+payload` | `http`/`limit` | yes |
| 13 | SMTP payload with 5 000 lines | `partial` | `SMTP` / `port+payload` | `smtp`/`limit` | yes |
| 14 | Random bytes on ports 80, 53, and 25 (3 packets) | `ok` | `UNKNOWN` / `none` | none | yes |
| 15 | Bytes that are invalid in UTF-8 and ASCII | `ok` | `UNKNOWN` / `none` | none | yes |
| 16 | Empty frame and 1-byte frame (2 packets) | `unsupported` | `UNKNOWN` / `none` | none | no |
| 17 | IPv6, ARP, ICMP, GRE (4 packets) | `unsupported` | `UNKNOWN` / `none` | none | no |
| 18 | PCAP file whose last record is cut | `partial` | `UNKNOWN` / `none` | `transport`/`truncated` | yes |
| 19 | File that is not a PCAP file | no event | — | — | — |
| 20 | NULL link and LINUX_SLL link (1 file each) | `ok` | `HTTP` / `port` | none | yes |

Notes on the items without an error entry:

- **Items 09, 14, and 15:** the payload fails every detector rule, so `detection.method` is `none`, even on the well-known ports. The port alone does not decide the protocol (`DET-1`). Item 09 fails the DNS rule, because the detector accepts at most 16 questions.
- **Items 16 and 17:** the packet has no supported network or transport layer, so `status` is `unsupported`. `--unknown drop` removes these events, as R3.4 requires.
- **Item 19:** `PcapSource` logs `stopped reading …: Not a supported capture file`, and the run writes 0 events and exits with code 0 (R2.3).
- **Item 20:** the pipeline reads the link types `Loopback` and `LinuxSLL`. The inner packet is a TCP SYN to port 80, so `app_protocol` is `HTTP` from the port hint.

Items 01 and 03 keep `src_ip=10.0.0.1` and `dst_ip=10.0.0.2` in `network`, although the header length is invalid.

Wireshark confirms three sample items. For item 01 it reports a bogus IPv4 header length, as the `network`/`malformed` error does. For item 08 it reports a fault in the DNS answer name, as the `dns`/`malformed` error does. It cannot open item 19, because the file is not a capture file.

## Retest after Assignment 02

The retest reruns the command of this case with the program of Assignment 02. The base fields are unchanged: every event has the same values and the same key order as in the committed output before the retest. The retest adds ten keys to each event: `payload_hex`, `decode_status`, `decoded`, `preprocess_status`, `processing_action`, `reason`, `normalized`, `flow_id`, `direction`, and `processing_errors`. `console.txt` shows the new summary lines.

New values in this case:

- Every run writes the same number of events as before. The output files of item 19 (both policies) and of items 16 and 17 under `drop` are empty, so they are unchanged.
- A packet with a malformed or too short header has no usable transport layer. Items 01, 03, 04, 05, 07, 16, and 17 are `partial` with `skip_flow`, and the tracker does not read them. The reason is `no transport layer`. Items 16 and 17 give `no network layer; no transport layer` for the empty frames, the ARP packet, and the IPv6 packet, and `no transport layer` for the ICMP and GRE packets of item 17.
- Items 02, 06, 08, 10, 11, 12, 13, and 18 keep their flow fields. They are `partial` with `keep` and the reason `packet status is partial` or `packet status is malformed`. These events join a flow.
- The decoder adds one typed entry to `processing_errors`: the type `limit` for item 11 (the 20 KB request line) and item 13 (5 000 SMTP lines). The decoder cut its input there. No other event has a `processing_errors` entry.
- The decoder reports `partial` for item 09, for the 3 packets of item 14, and for item 15, because their payloads are binary (reason `binary payload`). These events are `valid` with `keep`. Every other event has `decode_status` `not_applicable`.
- Items 20 (the two link types) are `valid` with `keep`, as normal packets.
- With `drop`, every item except 16, 17, and 19 writes the same events as with `keep`, byte for byte. Items 16 and 17 write none, and item 19 never wrote any.

The tables above describe the base fields and stay valid. The field `errors` is the parser list of Assignment 01. The new list `processing_errors` is separate. No Wireshark check is repeated, because no base field changed.

## Verdict

PASS.
