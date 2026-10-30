# A3-T08 — Flow to_server, established

## Purpose

The rule option `flow:to_server,established` must use the state of the Flow Tracker. It must match client data only after the handshake. This is test case 8 of the description. A SYN, the server packets, and a second connection that is still in the handshake must not match.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t08_flow_established/`.

`traffic.pcap` (6 packets, 2 connections):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.1:40000 → 10.0.0.2:80 | SYN | 0 | 54 |
| 2 | 0.5 | 10.0.0.2:80 → 10.0.0.1:40000 | SYN, ACK | 0 | 54 |
| 3 | 1.0 | 10.0.0.1:40000 → 10.0.0.2:80 | ACK | 0 | 54 |
| 4 | 1.5 | 10.0.0.1:40000 → 10.0.0.2:80 | PSH, ACK | 47 (client data, `GET /index.html HTTP/1.1`) | 101 |
| 5 | 2.0 | 10.0.0.2:80 → 10.0.0.1:40000 | PSH, ACK | 38 (server data, `HTTP/1.1 200 OK`) | 92 |
| 6 | 2.5 | 10.0.0.3:41000 → 10.0.0.2:80 | SYN | 0 | 54 |

Packets 1 to 5 are one connection. Packet 6 is a bare SYN of a second connection.

`local.rules` holds one rule:

```text
alert tcp any any <> any 80 (msg:"Client data on an established flow"; flow:to_server,established; dsize:>0; sid:100801; rev:1;)
```

The `<>` header accepts both directions, so the header passes for all 6 packets. The flow option and `dsize:>0` decide. `dsize:>0` keeps the empty ACK of the handshake out of the match.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T08_flow_established/input/traffic.pcap --rules-config TEST/assignment-03/A3-T08_flow_established/input/rules.toml --output TEST/assignment-03/A3-T08_flow_established/output/events.jsonl --flows-output TEST/assignment-03/A3-T08_flow_established/output/flows.jsonl --matches-output TEST/assignment-03/A3-T08_flow_established/output/matches.jsonl --rules-report TEST/assignment-03/A3-T08_flow_established/output/rules_report.jsonl
```

## Expected result

| Packet | State of the flow after the packet | Direction | Result |
|---|---|---|---|
| 1 | `HANDSHAKE` | to server | No match: not established (`rejected by flow`) |
| 2 | `HANDSHAKE` | to client | No match: wrong direction (`rejected by flow`) |
| 3 | `ESTABLISHED` | to server | No match: `dsize` is 0 (`rejected by packet options`) |
| 4 | `ESTABLISHED` | to server | **Match** |
| 5 | `ESTABLISHED` | to client | No match: wrong direction (`rejected by flow`) |
| 6 | `HANDSHAKE` (new flow) | to server | No match: not established (`rejected by flow`) |

- The summary shows `records evaluated: 6`, `candidate rules: 6`, `rejected by header: 0`, `rejected by flow: 4`, `rejected by packet options: 1`, `rejected by content: 0`, `rule matches: 1`.
- `matches.jsonl` holds one rule match: packet 4, sid 100801, with `flow_state="ESTABLISHED"`.
- The run exits with code 0.

## Actual result

The summary shows `records evaluated: 6`, `candidate rules: 6`, `rejected by header: 0`, `rejected by flow: 4`, `rejected by packet options: 1`, `rejected by content: 0`, `rule matches: 1`, `engine errors: 0`. The exit code is 0.

`matches.jsonl` holds one rule match: `packet_id=4`, `sid=100801`, `flow_id="tcp-5f8ec36d79cc"`, `direction="forward"`, `flow_state="ESTABLISHED"`, `matched` = `flow "to_server,established"` and `dsize ">0"`.

`flows.jsonl` holds 2 flow records: `tcp-5f8ec36d79cc` (5 packets, state `ESTABLISHED`) and `tcp-78fbd04a887b` (1 packet, state `HANDSHAKE`).

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.1 10.0.0.2 TCP 40000  80  ··········S· 0  54 40000\ →\ 80\ [SYN]\ Seq=0\ Win=8192\ Len=0
2 0.500000000 10.0.0.2 10.0.0.1 TCP 80  40000  ·······A··S· 0  54 80\ →\ 40000\ [SYN,\ ACK]\ Seq=0\ Ack=1\ Win=8192\ Len=0
3 1.000000000 10.0.0.1 10.0.0.2 TCP 40000  80  ·······A···· 0  54 40000\ →\ 80\ [ACK]\ Seq=1\ Ack=1\ Win=8192\ Len=0
4 1.500000000 10.0.0.1 10.0.0.2 HTTP 40000  80  ·······AP··· 47  101 GET\ /index.html\ HTTP/1.1\ 
5 2.000000000 10.0.0.2 10.0.0.1 HTTP 80  40000  ·······AP··· 38  92 HTTP/1.1\ 200\ OK\ 
6 2.500000000 10.0.0.3 10.0.0.2 TCP 41000  80  ··········S· 0  54 41000\ →\ 80\ [SYN]\ Seq=0\ Win=8192\ Len=0
-- problems (expert or malformed, checksums checked):
       0
10.0.0.1:40000             <-> 10.0.0.2:80                      2 146 bytes       3 209 bytes       5 355 bytes     0.000000000         2.0000
10.0.0.3:41000             <-> 10.0.0.2:80                      0 0 bytes         1 54 bytes        1 54 bytes      2.500000000         0.0000
```

Wireshark shows the flags `[SYN]`, `[SYN, ACK]`, `[ACK]`, and two `[PSH, ACK]` packets with 47 and 38 bytes of payload on the first connection, and a `[SYN]` on the second one. It shows 2 TCP conversations: 10.0.0.1:40000 ↔ 10.0.0.2:80 with 5 frames, and 10.0.0.3:41000 ↔ 10.0.0.2:80 with 1 frame. This agrees with the 2 flow records. The expert and malformed filter finds no problem.

Wireshark does not show the state of the flow. The state follows from the flags: the SYN starts `HANDSHAKE`, and the ACK of packet 3 moves the flow to `ESTABLISHED`. The engine reads the state after the packet, so packet 3 is already established. The rule needs data, so `dsize:>0` stops it.

## Verdict

PASS. Only the client data of packet 4, after the handshake, matches `flow:to_server,established`. The SYN packets, the server packets, and the empty ACK do not match, and each stops at the stage in the table.
