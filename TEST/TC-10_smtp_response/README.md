# TC-10 — SMTP response

## Purpose

The parser must parse the SMTP status code of a server response, including a multi-line response.

## Input

`input.pcap` is a copy of `tests/fixtures/smtp_session.pcap`, the same session as TC-09. TC-09 checks the client commands. This case checks the server responses.

The server is 10.0.0.2:25, and the client is 10.0.0.1:40000. The server sends these payloads, one per segment:

| Packet | Server payload | Answers |
|---|---|---|
| 1 | `220 mail.example.com ESMTP` | the connection (greeting) |
| 3 | `250-mail.example.com`, `250-SIZE 10240000`, `250-STARTTLS`, `250 HELP` | `EHLO` |
| 5 | `250 OK` | `MAIL FROM` |
| 7 | `250 OK` | `RCPT TO` |
| 9 | `354 End data with <CR><LF>.<CR><LF>` | `DATA` |
| 11 | `250 Message accepted` | the message content |
| 13 | `221 Bye` | `QUIT` |

Every line ends with CRLF. A reply line is a 3-digit code, then a separator, then text (RFC 5321 section 4.2). The separator `-` means that more lines of the same reply follow. The separator space marks the last line.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-10_smtp_response/input.pcap --output TEST/TC-10_smtp_response/output.jsonl
```

## Expected result

- The run writes 13 events and exits with code 0.
- Every server packet has `app_protocol="SMTP"`, `detection.method="port+payload"`, and `detection.rule="smtp_response"`. The port hint comes from the source port 25.
- Every server packet has `application.kind="response"`, and every line has the code shown in the Input table.
- Packet 3 has `application.multiline=true` and 4 lines with code 250. The separators are `-`, `-`, `-`, and a space.
- Every other server packet has `application.multiline=false` and 1 line.
- Every event has `status="ok"` and no errors.

## Actual result

`output.jsonl` holds 13 events. `console.txt` holds the console summary and the exit code 0.

Server packets:

| `packet_id` | `application.multiline` | `lines[].code` | `lines[].separator` | `lines[].message` |
|---|---|---|---|---|
| 1 | `false` | 220 | space | `mail.example.com ESMTP` |
| 3 | `true` | 250, 250, 250, 250 | `-`, `-`, `-`, space | `mail.example.com`, `SIZE 10240000`, `STARTTLS`, `HELP` |
| 5 | `false` | 250 | space | `OK` |
| 7 | `false` | 250 | space | `OK` |
| 9 | `false` | 354 | space | `End data with <CR><LF>.<CR><LF>` |
| 11 | `false` | 250 | space | `Message accepted` |
| 13 | `false` | 221 | space | `Bye` |

All 13 events have `status="ok"` and no errors. The codes cover two reply classes: 2yz (success: 220, 250, 221) and 3yz (intermediate: 354, the server waits for the message content).

Except for `source`, `output.jsonl` is the same as the output of TC-09, because both cases read the same session.

Wireshark shows the same responses: codes 220, 250, 354, and 221 with the same text. For packet 3 it shows 4 response lines with code 250, and the first 3 lines have the `-` separator.

## Verdict

PASS.
