# A3-T14 — Rule match record

## Purpose

A rule match must hold every field that section 4.6 of the description requires. This is test case 14. The project calls the output record a "rule match" (decision D1). It is the "Detection Event" of the description. The case uses the example of section 5 of the description: a request with `content:"../"`, with the client 10.0.0.5:52133 and the server 192.168.1.20:80.

## Input

`input/` holds `traffic.pcap`, `local.rules`, and `rules.toml`. The script `tests/fixtures/build_pcaps.py` generates the pcap. The other files are copies from `tests/fixtures/rules/t14_match_record/`.

`traffic.pcap` (4 packets, one connection):

| Packet | Time (s) | Direction | Flags | Payload (bytes) | Frame length (bytes) |
|---|---|---|---|---|---|
| 1 | 0.0 | 10.0.0.5:52133 → 192.168.1.20:80 | SYN | 0 | 54 |
| 2 | 0.5 | 192.168.1.20:80 → 10.0.0.5:52133 | SYN, ACK | 0 | 54 |
| 3 | 1.0 | 10.0.0.5:52133 → 192.168.1.20:80 | ACK | 0 | 54 |
| 4 | 1.5 | 10.0.0.5:52133 → 192.168.1.20:80 | PSH, ACK | 56 (`GET /files/../etc/passwd HTTP/1.1`, a `Host` header) | 110 |

`local.rules` holds one rule:

```text
alert tcp 10.0.0.0/24 any -> any 80 (msg:"Directory traversal detected"; flow:to_server,established; content:"../"; classtype:web-application-attack; priority:1; sid:100001; rev:1;)
```

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/assignment-03/A3-T14_match_record/input/traffic.pcap --rules-config TEST/assignment-03/A3-T14_match_record/input/rules.toml --output TEST/assignment-03/A3-T14_match_record/output/events.jsonl --flows-output TEST/assignment-03/A3-T14_match_record/output/flows.jsonl --matches-output TEST/assignment-03/A3-T14_match_record/output/matches.jsonl --rules-report TEST/assignment-03/A3-T14_match_record/output/rules_report.jsonl
```

## Expected result

- The run exits with code 0.
- Packet 4 matches. The flow is established after the handshake, and the payload holds `../` at byte 11 (`GET /files/` takes bytes 0 to 10).
- The other packets stop before the match: packet 1 (SYN) fails on the flow state, packet 2 (SYN/ACK from the server) fails on the header because 192.168.1.20 is not in 10.0.0.0/24, and packet 3 (ACK) fails on the content. So `rejected by header: 1`, `rejected by flow: 1`, `rejected by content: 1`, `rule matches: 1`, and `candidate rules: 4`.
- `matches.jsonl` holds one rule match. It has all the fields of the next table.

| Field of the description | Field of the rule match | Expected value |
|---|---|---|
| timestamp | `timestamp`, `timestamp_iso` | `1758441601.5`, `2025-09-21T08:00:01.500000+00:00` (packet 4 at 1.5 s) |
| sid | `sid` | `100001` |
| rev | `rev` | `1` |
| msg | `msg` | `Directory traversal detected` |
| priority | `priority` | `1` |
| classtype | `classtype` | `web-application-attack` |
| protocol | `protocol` | `TCP` |
| source IP and port | `src_ip`, `src_port` | `10.0.0.5`, `52133` |
| destination IP and port | `dst_ip`, `dst_port` | `192.168.1.20`, `80` |
| application_protocol | `application_protocol` | `HTTP` |
| flow_id | `flow_id` | The id of the flow of the 4 packets |
| match info | `matched` | `content "../"` at position 11, and `flow "to_server,established"` |

The record has four more fields: `direction` (`forward`), `flow_state` (`ESTABLISHED`), `packet_id` (4), and `source` (the pcap path).

## Actual result

The summary shows `records evaluated: 4`, `candidate rules: 4`, `rejected by header: 1`, `rejected by flow: 1`, `rejected by packet options: 0`, `rejected by content: 1`, `rule matches: 1`, `engine errors: 0`. The exit code is 0.

`matches.jsonl` holds this one line:

```json
{
  "timestamp": 1758441601.5,
  "timestamp_iso": "2025-09-21T08:00:01.500000+00:00",
  "sid": 100001,
  "rev": 1,
  "msg": "Directory traversal detected",
  "classtype": "web-application-attack",
  "priority": 1,
  "protocol": "TCP",
  "src_ip": "10.0.0.5",
  "src_port": 52133,
  "dst_ip": "192.168.1.20",
  "dst_port": 80,
  "application_protocol": "HTTP",
  "flow_id": "tcp-bbd9b7aed86f",
  "direction": "forward",
  "flow_state": "ESTABLISHED",
  "packet_id": 4,
  "source": "pcap:TEST/assignment-03/A3-T14_match_record/input/traffic.pcap",
  "matched": [
    {"keyword": "flow", "value": "to_server,established", "position": null},
    {"keyword": "content", "value": "../", "position": 11}
  ]
}
```

Every field of the expected table is present with the expected value. The `flow_id` is the same as the `flow_id` of the 4 events in `events.jsonl` and of the flow record in `flows.jsonl`.

## Wireshark check

I ran `tshark` of Wireshark 4.6.9 on `input/traffic.pcap`, with the checksum checks on. The `tshark` output:

```text
1 0.000000000 10.0.0.5 192.168.1.20 TCP 52133  80  ··········S· 0  54 52133\ →\ 80\ [SYN]\ Seq=0\ Win=8192\ Len=0
2 0.500000000 192.168.1.20 10.0.0.5 TCP 80  52133  ·······A··S· 0  54 80\ →\ 52133\ [SYN,\ ACK]\ Seq=0\ Ack=1\ Win=8192\ Len=0
3 1.000000000 10.0.0.5 192.168.1.20 TCP 52133  80  ·······A···· 0  54 52133\ →\ 80\ [ACK]\ Seq=1\ Ack=1\ Win=8192\ Len=0
4 1.500000000 10.0.0.5 192.168.1.20 HTTP 52133  80  ·······AP··· 56  110 GET\ /files/../etc/passwd\ HTTP/1.1\ 
-- problems (expert or malformed, checksums checked):
       0
10.0.0.5:52133             <-> 192.168.1.20:80                  1 54 bytes        3 218 bytes       4 272 bytes     0.000000000         1.5000
```

Wireshark shows the handshake `[SYN]`, `[SYN, ACK]`, `[ACK]`, and then an HTTP request `GET /files/../etc/passwd HTTP/1.1` with a 56-byte payload from 10.0.0.5:52133 to 192.168.1.20:80. It shows one TCP conversation with 4 frames, and the relative time of the request is 1.5 s. This agrees with the addresses, ports, protocol, packet number, and timestamp of the rule match. The expert and malformed filter finds no problem.

Wireshark does not show the flow state or the flow id. The state follows from the handshake: the ACK of packet 3 makes the flow `ESTABLISHED` before the request.

## Verdict

PASS. The rule match holds the sid, rev, msg, priority, classtype, the 5-tuple and protocol, the application protocol, the flow id, and the matched content `../`. All values agree with the pcap in Wireshark.
