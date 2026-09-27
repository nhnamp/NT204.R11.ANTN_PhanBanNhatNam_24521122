# TC-09 — SMTP command

## Purpose

The parser must parse SMTP commands: `HELO`/`EHLO`, `MAIL FROM`, and `RCPT TO`.

## Input

`input.pcap` is a copy of `tests/fixtures/smtp_session.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time. TC-10 uses the same session and checks the server responses.

The file holds a complete SMTP session in 13 TCP segments. The client is 10.0.0.1:40000, and the server is 10.0.0.2:25. The client sends these payloads, one per segment:

| Packet | Client payload |
|---|---|
| 2 | `EHLO client.example.com` |
| 4 | `MAIL FROM:<alice@example.com>` |
| 6 | `RCPT TO:<bob@example.com>` |
| 8 | `DATA` |
| 10 | `Hello Bob.` and the end-of-data line `.` |
| 12 | `QUIT` |

Every line ends with CRLF. The odd packets are the server responses.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-09_smtp_command/input.pcap --output TEST/TC-09_smtp_command/output.jsonl
```

## Expected result

- The run writes 13 events and exits with code 0.
- Every command packet has `app_protocol="SMTP"`, `detection.method="port+payload"`, and `detection.rule="smtp_command"`.
- Every command packet has `application.kind="command"` and one line with `kind="command"`.
- `EHLO`: `command="EHLO"`, `argument="client.example.com"`.
- `MAIL FROM`: `command="MAIL FROM"`, `argument="<alice@example.com>"`.
- `RCPT TO`: `command="RCPT TO"`, `argument="<bob@example.com>"`.
- Every event has `status="ok"` and no errors.

## Actual result

`output.jsonl` holds 13 events. `console.txt` holds the console summary and the exit code 0.

Client packets:

| `packet_id` | `detection.rule` | `application.kind` | `lines[0].command` | `lines[0].argument` |
|---|---|---|---|---|
| 2 | `smtp_command` | `command` | `EHLO` | `client.example.com` |
| 4 | `smtp_command` | `command` | `MAIL FROM` | `<alice@example.com>` |
| 6 | `smtp_command` | `command` | `RCPT TO` | `<bob@example.com>` |
| 8 | `smtp_command` | `command` | `DATA` | `""` |
| 10 | — | — (`application=null`) | — | — |
| 12 | `smtp_command` | `command` | `QUIT` | `""` |

All 13 events have `status="ok"` and no errors. `MAIL FROM` and `RCPT TO` are two tokens on the wire, but each is one command. The argument is the text after the colon.

Packet 10 carries only message content, so it matches no detector rule. It has `app_protocol="UNKNOWN"`, `detection.method="none"`, and `application=null`. The parser has no session state, so it cannot know that this packet follows `DATA` (R8.2).

Wireshark shows the same commands: `EHLO client.example.com`, `MAIL FROM:<alice@example.com>`, `RCPT TO:<bob@example.com>`, `DATA`, and `QUIT`. It splits a command at the first space, so it shows `MAIL` with the parameter `FROM:<alice@example.com>`. The parser keeps `MAIL FROM` as one command (R8.4). Wireshark decodes packet 10 as message data, because it tracks the TCP session state.

## Verdict

PASS.
