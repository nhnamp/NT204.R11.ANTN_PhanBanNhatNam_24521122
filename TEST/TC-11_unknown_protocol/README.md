# TC-11 — Unknown protocol

## Purpose

The program must not crash on a protocol that it does not support (`PIPE-2`, `ERR-1`). It must mark the packet as `UNKNOWN`, or skip it, as the configuration selects (`PIPE-3`).

## Input

`input.pcap` is a copy of `tests/fixtures/unknown_protocols.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with fixed times and a fixed random seed.

| Packet | Content | Unsupported at |
|---|---|---|
| 1 | IPv6 / TCP SYN, 2001:db8::1 → 2001:db8::2 | network layer (only IPv4 is supported) |
| 2 | ARP request, 10.0.0.1 asks for 10.0.0.2 | network layer (not IP) |
| 3 | IPv4 / ICMP echo request with the payload `ping` | transport layer (IP protocol 1) |
| 4 | IPv4 / GRE / an inner IPv4 TCP packet | transport layer (IP protocol 47) |
| 5 | IPv4 / TCP to port 4444, 64 random payload bytes | application layer (no rule matches) |

## Commands

Run the commands from the repository root. The first command uses the default policy, `keep`. The second command uses `drop`.

```bash
python main.py --pcap TEST/TC-11_unknown_protocol/input.pcap --output TEST/TC-11_unknown_protocol/output.jsonl --unknown keep
```

```bash
python main.py --pcap TEST/TC-11_unknown_protocol/input.pcap --output TEST/TC-11_unknown_protocol/output_drop.jsonl --unknown drop
```

## Expected result

- Both runs read 5 packets, print the summary, and exit with code 0. No traceback appears.
- With `keep`, the run writes 5 events. Every event has `app_protocol="UNKNOWN"`, `detection.method="none"`, and no errors.
- Packets 1 to 4 have `status="unsupported"`. Packets 3 and 4 keep their IPv4 fields in `network`.
- Packet 5 has `status="ok"`: TCP is a supported protocol, and only the application is unknown (R5.1).
- With `drop`, the run writes only packet 5 and counts 4 dropped packets. `--unknown drop` removes only the events with `status="unsupported"` (R3.4, R4.1).

## Actual result

`output.jsonl` holds the 5 events of the `keep` run. `output_drop.jsonl` holds the 1 event of the `drop` run. `console.txt` holds both commands, both summaries, and both exit codes.

| `packet_id` | `status` | `app_protocol` | `detection.method` | `network` | `transport` | `errors` |
|---|---|---|---|---|---|---|
| 1 | `unsupported` | `UNKNOWN` | `none` | `null` | `null` | `[]` |
| 2 | `unsupported` | `UNKNOWN` | `none` | `null` | `null` | `[]` |
| 3 | `unsupported` | `UNKNOWN` | `none` | IPv4, `proto_name="ICMP"` | `null` | `[]` |
| 4 | `unsupported` | `UNKNOWN` | `none` | IPv4, `proto_name="47"` | `null` | `[]` |
| 5 | `ok` | `UNKNOWN` | `none` | IPv4, `proto_name="TCP"` | TCP, port 4444, 64 bytes | `[]` |

| Run | Events written | `ok` | `unsupported` | `dropped` | Exit code |
|---|---|---|---|---|---|
| `keep` | 5 | 1 | 4 | 0 | 0 |
| `drop` | 1 (packet 5) | 1 | 0 | 4 | 0 |

`proto_name` is `"47"` for GRE, because the parser names only ICMP, TCP, and UDP, and writes any other protocol number as a string (R3.2).

The `packet_id` of the event in `output_drop.jsonl` is 5, not 1. The counter counts every packet read, so a gap in the ids shows the dropped packets.

Wireshark shows the same 5 packets: TCP over IPv6, an ARP request, an ICMP echo request, a GRE packet that carries an inner IPv4 TCP packet, and a TCP segment to port 4444 with 64 data bytes. Wireshark decodes the inner packet of GRE. The parser stops at GRE, because GRE is not a supported protocol.

## Verdict

PASS.
