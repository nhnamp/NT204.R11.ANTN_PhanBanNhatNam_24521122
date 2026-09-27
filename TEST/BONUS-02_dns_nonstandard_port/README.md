# BONUS-02 — DNS on a non-standard port

## Purpose

The detector must recognise DNS on a port other than 53 (`DET-4`), over UDP and over TCP. DNS has no text keyword, so the detector checks the binary structure of the message (R5.3).

## Input

`input/` holds copies of two fixtures from `tests/fixtures/`. The script `tests/fixtures/build_pcaps.py` generates them with fixed times. Neither port is in the hint table (R5.4).

| File | Transport and port | Packets |
|---|---|---|
| `bonus_dns_1053.pcap` | UDP 1053 | 2: an A query for `example.com` (ID `0x4321`) and its response with one answer |
| `bonus_dns_tcp_9053.pcap` | TCP 9053 | 1: the same query, with the 2-byte length prefix of DNS over TCP |

## Commands

Run the commands from the repository root.

```bash
python main.py --pcap TEST/BONUS-02_dns_nonstandard_port/input/bonus_dns_1053.pcap --output TEST/BONUS-02_dns_nonstandard_port/output/bonus_dns_1053.jsonl
```

```bash
python main.py --pcap TEST/BONUS-02_dns_nonstandard_port/input/bonus_dns_tcp_9053.pcap --output TEST/BONUS-02_dns_nonstandard_port/output/bonus_dns_tcp_9053.jsonl
```

## Expected result

- Both runs exit with code 0, and every event has `status="ok"` and no errors.
- Every event has `app_protocol="DNS"`, `detection.method="payload"`, and `detection.confidence="high"`.
- `detection.rule` is `dns_udp` on port 1053 and `dns_tcp` on port 9053.
- The DNS parser fills `application` on every packet, the same as on port 53.

## Actual result

`output/` holds one JSON Lines file per input. `console.txt` holds both commands, their summaries, and their exit codes.

| File | `packet_id` | Direction | `detection.method` | `detection.rule` | `application` |
|---|---|---|---|---|---|
| `bonus_dns_1053` | 1 | UDP 40000 → **1053** | `payload` | `dns_udp` | query `0x4321`, flags `["RD"]`, question `example.com` A |
| `bonus_dns_1053` | 2 | UDP **1053** → 40000 | `payload` | `dns_udp` | response `0x4321`, flags `["RD", "RA"]`, answer `example.com` A 300 `93.184.216.34` |
| `bonus_dns_tcp_9053` | 1 | TCP 40000 → **9053** | `payload` | `dns_tcp` | query `0x4321`, flags `["RD"]`, question `example.com` A |

Every event has `app_protocol="DNS"`, `detection.confidence="high"`, `status="ok"`, and no errors.

The TCP payload is 31 bytes: the 2-byte length prefix (29) and the same 29-byte query as on UDP. The `dns_tcp` rule accepts the payload only when the prefix is equal to the remaining length. The parser then removes the prefix.

The detector cannot find a DNS keyword, because DNS is binary. It accepts the payload only when the header counts are plausible and the question name parses within bounds (R5.3). The same check rejects random bytes on port 53 (BONUS-04).

Wireshark decodes both UDP packets on port 1053 as DNS, with no setting: `Standard query 0x4321 A example.com` and `Standard query response 0x4321 A example.com A 93.184.216.34`. On TCP port 9053 it shows only TCP. The parser recognises DNS on both ports, because it checks the DNS structure instead of a port list.

## Verdict

PASS.
