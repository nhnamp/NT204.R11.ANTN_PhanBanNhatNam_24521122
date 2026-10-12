# A2-T03 — SMTP MIME decode

## Purpose

The Decoder must decode a Base64 body and a Quoted-Printable body of an SMTP message (`DEC-4`). The messages have no `charset` parameter, so the Decoder reads the decoded bytes as UTF-8. It must record the methods in the order in which it applied them.

## Input

`input.pcap` is a copy of `tests/fixtures/smtp_mime.pcap`. It holds 21 TCP packets of one SMTP dialogue between `10.0.0.1:40000` (client) and `10.0.0.2:25` (server). The dialogue sends two messages.

| Packet | Direction | Frame length (bytes) | Payload (bytes) | Content |
|---|---|---|---|---|
| 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21 | server → client | 62 to 119 | 8 to 65 | Server replies (`220`, `250`, `354`, `221`) |
| 2, 4, 6, 8, 12, 14, 16, 20 | client → server | 60 to 85 | 6 to 31 | Commands (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, `QUIT`) |
| 10 | client → server | 238 | 184 | Message 1: headers, `Content-Transfer-Encoding: base64`, body `WGluIGNow6BvIEJvYg0K`, final `.` |
| 18 | client → server | 261 | 207 | Message 2: headers, `Content-Transfer-Encoding: quoted-printable`, body `caf=C3=A9 1+1=3D2, a long li=` + CRLF + `ne`, final `.` |

Packets 10 and 18 are the only two packets with a message body.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T03_smtp_mime/input.pcap --output TEST/A2-T03_smtp_mime/output.jsonl
```

The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

## Expected result

A hand calculation with the Python functions `base64.b64decode` and `quopri.decodestring` gives the expected values.

| Packet | Encoded body | Expected `value` | `methods` |
|---|---|---|---|
| 10 | `WGluIGNow6BvIEJvYg0K` | `Xin chào Bob` + CRLF (15 bytes) | `base64`, `charset:utf-8` |
| 18 | `caf=C3=A9 1+1=3D2, a long li=` + CRLF + `ne` | `café 1+1=2, a long line` + CRLF | `quoted-printable`, `charset:utf-8` |

In packet 18, `=C3=A9` is the UTF-8 form of `é`, `=3D` is `=`, and the soft line break `=` + CRLF joins `li` and `ne`.

Other fields:
- The run writes 21 events and exits with code 0.
- The two events of packets 10 and 18 have the field `mime.body` and `decode_status="ok"`.
- The other 19 events have `decode_status="not_applicable"` and no item.
- All 21 events have the same `flow_id`.

## Actual result

`output.jsonl` holds 21 events, and `console.txt` holds the console summary and the exit code 0. All events have `status="ok"`, `preprocess_status="valid"`, and `processing_action="keep"`.

| Packet | Item `field` | Decoded `value` | `methods` | Item `status` |
|---|---|---|---|---|
| 10 | `mime.body` | `Xin chào Bob` + CRLF | `base64`, `charset:utf-8` | `ok` |
| 18 | `mime.body` | `café 1+1=2, a long line` + CRLF | `quoted-printable`, `charset:utf-8` | `ok` |

The flow id of all events is `tcp-f18001be8382`. The `app_protocol` of packets 10 and 18 is `UNKNOWN`, because the Application Protocol Detector has no parser for the message part after `DATA`. The decoder reads the MIME headers from the payload on its own.

## Wireshark check

The packets of `input.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison. All packets share one 5-tuple and have unrelated sequence numbers. The Follow TCP Stream view therefore shows only packets 1 and 2 (28 and 25 bytes). Wireshark marks most packets as `[TCP Previous segment not captured]`. This does not change the packet bytes, so the packet list and the packet bytes are the evidence.

| Packet | Wireshark Info | Wireshark length | Wireshark TCP payload (bytes) | `length` of the event | `payload_len` of the event | Payload bytes equal | Match |
|---|---|---|---|---|---|---|---|
| 10 | from: alice@example.com, subject: NT204, (text/plain), protocol SMTP/IMF | 238 | 184 | 238 | 184 | yes | yes |
| 18 | from: alice@example.com, subject: NT204, (text/plain), protocol SMTP/IMF | 261 | 207 | 261 | 207 | yes | yes |

The other 19 packets also match the events in source, destination, ports, frame length, TCP payload length, and payload bytes.

For packet 10, Wireshark dissects the body as Base64. Its own Base64 tab shows 15 bytes, and these bytes equal the decoded `value` of the event.

## Verdict

PASS. Both MIME bodies decode to the expected text. The methods appear in the expected order. The packets and the payload bytes equal the Wireshark values.
