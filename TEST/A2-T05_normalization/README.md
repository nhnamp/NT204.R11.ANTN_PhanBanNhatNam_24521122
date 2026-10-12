# A2-T05 — Normalization

## Purpose

The Preprocessor must give a consistent `normalized` view for data in a different letter case or format (`PRE-3`). The protocol name, the IP address, the domain, the HTTP header name, the path, and the timestamp must come out in one form.

## Input

This case uses a folder, because it has two kinds of input: a PCAP file and an events file.

`input/normalization.pcap` is a copy of `tests/fixtures/normalization.pcap`. It holds three packets from `10.0.0.1:40000` to `10.0.0.2`.

| Packet | Transport | Frame length (bytes) | Payload (bytes) | Content |
|---|---|---|---|---|
| 1 | TCP, port 80 | 131 | 77 | `GET /a/%2e%2e/b?q=1`, headers `HOST: EXAMPLE.com.:80`, `X-Test: a`, `x-TEST: b` |
| 2 | TCP, port 80 | 118 | 64 | `GET /b?q=1`, headers `host: example.com`, `x-test: a`, `x-test: b` |
| 3 | UDP, port 53 | 75 | 33 | DNS query for `WWW.Example.COM` |

Packets 1 and 2 ask for the same page and the same host in a different form.

`input/protocol_and_ip.jsonl` is a copy of `tests/fixtures/events/protocol_and_ip.jsonl`. It holds three records. The records have no `application` and no `length`.

| Record | Timestamp | Protocol | `app_protocol` | Source IP | Ports | Flags |
|---|---|---|---|---|---|---|
| 1 | `1758441600.0` | `TCP` | `HTTP` | `2001:db8::1` | `40000`, `80` (numbers) | `SYN` |
| 2 | `"2025-09-21T08:00:00"` (no zone) | `tcp` | `Http` | `2001:DB8::1` | `"40000"`, `"80"` (strings) | `syn` |
| 3 | `1758441600.0` | `TCP` | `HTTP` | `010.0.0.1` | `40000`, `80` | `SYN` |

Records 1 and 2 hold the same event in a different form. Record 3 has a leading zero in the IPv4 address.

## Commands

Run the commands from the repository root. The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

```bash
python main.py --pcap TEST/A2-T05_normalization/input/normalization.pcap --output TEST/A2-T05_normalization/output/normalization.jsonl
```

```bash
python main.py --events TEST/A2-T05_normalization/input/protocol_and_ip.jsonl --output TEST/A2-T05_normalization/output/protocol_and_ip.jsonl
```

## Expected result

The expected values follow from the normalization rules of `PRE-3` and from the input above. A hand calculation with the Python standard library gives the same values: `ipaddress.ip_address` turns `2001:DB8::1` into `2001:db8::1` and rejects `010.0.0.1`, `urllib.parse.unquote` and `posixpath.normpath` turn `/a/%2e%2e/b` into `/b`, and a naive ISO time read as UTC gives `1758441600.0`.

**PCAP file.**

| Item | Packet 1 | Packet 2 | Packet 3 |
|---|---|---|---|
| `normalized.host` | `example.com` | `example.com` | `null` |
| `normalized.path` | `/b` | `/b` | `null` |
| `normalized.query` | `q=1` | `q=1` | `null` |
| `normalized.headers` | names in lower case, `x-test` is `["a", "b"]` | the same | `{}` |
| `normalized.domains` | `[]` | `[]` | `["www.example.com"]` |
| `normalized.protocol` | `TCP` | `TCP` | `UDP` |

- For packet 1, the host loses its port `:80`, its trailing dot, and its capital letters. The path loses the dot segment: `/a/../b` is `/b`.
- Packets 1 and 2 give the same `host`, `path`, `query`, and `x-test` list, although their raw text differs.
- The raw fields stay unchanged. For packet 1, `application.host` is `EXAMPLE.com.:80` and `application.target` is `/a/%2e%2e/b?q=1`.
- All 3 events are `valid` and `keep`. Packets 1 and 2 have one `flow_id`. Packet 3 has another.

**Events file.**

- Records 1 and 2 give the same `normalized` object: timestamp `1758441600.0`, `timestamp_iso` `2025-09-21T08:00:00+00:00`, protocol `TCP`, source IP `2001:db8::1`, ports `40000` and `80` as numbers, flags `["SYN"]`, `app_protocol` `HTTP`.
- Both records are `valid` and `keep`, and they have one `flow_id`.
- Record 3 gives `src_ip` `null`, because a leading zero is not a canonical IPv4 address. The record is `partial` with `skip_flow` and the reason `address is missing or invalid`. It has no `flow_id`.
- The raw fields stay as they are. Record 2 keeps `"tcp"`, `"Http"`, and the string ports.
- The run writes 3 events and exits with code 0.

Limit of this check: `normalized.headers` keeps the header values as they are, except that it strips the white space. The value `EXAMPLE.com.:80` stays in `headers.host`. Only `normalized.host` is normalized.

## Actual result

`output/normalization.jsonl` and `output/protocol_and_ip.jsonl` each hold 3 events. `console.txt` holds both commands, their summaries, and the exit codes 0.

**PCAP file.** The values equal the Expected result table. The flow ids are `tcp-5f8ec36d79cc` (packets 1 and 2) and `udp-87835d877a78` (packet 3). All 3 events are `valid` with `processing_action="keep"`. Packet 1 has the decoded item `http.target` with the value `/a/../b?q=1` (method `percent`), and the path of the `normalized` object is `/b`.

**Events file.**

| Record | `preprocess_status` | `processing_action` | `reason` | `flow_id` | `normalized.src_ip` |
|---|---|---|---|---|---|
| 1 | `valid` | `keep` | `null` | `tcp-58d9489f0581` | `2001:db8::1` |
| 2 | `valid` | `keep` | `null` | `tcp-58d9489f0581` | `2001:db8::1` |
| 3 | `partial` | `skip_flow` | `address is missing or invalid` | `null` | `null` |

The `normalized` objects of records 1 and 2 are equal. Record 2 still shows `"tcp"` and `"Http"` in its raw fields.

## Wireshark check

The packets of `normalization.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The events file is not a capture file, so it has no Wireshark part.

The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison. Wireshark marks packet 2 as `[TCP Previous segment not captured]`, because packets 1 and 2 share one 5-tuple and their sequence numbers are unrelated. This does not change the packet bytes.

| Packet | Wireshark source → destination | Wireshark length | Wireshark TCP or UDP payload (bytes) | `length` of the event | `payload_len` of the event | Payload bytes equal | Match |
|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | 131 | 77 | 131 | 77 | yes | yes |
| 2 | 10.0.0.1:40000 → 10.0.0.2:80 | 118 | 64 | 118 | 64 | yes | yes |
| 3 | 10.0.0.1:40000 → 10.0.0.2:53 | 75 | 33 | 75 | 33 | yes | yes |

The raw input of the normalization is visible in Wireshark:
- The packet bytes of packet 1 show `HOST: EXAMPLE.com.:80` and `x-TEST: b`. The packet bytes of packet 2 show `host: example.com` and `x-test: b`.
- The HTTP host field of Wireshark is `EXAMPLE.com.:80` for packet 1 and `example.com` for packet 2. The request URI is `/a/%2e%2e/b?q=1` and `/b?q=1`.
- The DNS query name of packet 3 is `WWW.Example.COM`.

## Verdict

PASS. Packets 1 and 2 give the same `host`, `path`, `query`, and `x-test` list, although their raw text differs. The two forms of the same event in the events file give equal `normalized` objects. The leading-zero address gives `null`, `partial`, and `skip_flow`. The packets and the payload bytes equal the Wireshark values.
