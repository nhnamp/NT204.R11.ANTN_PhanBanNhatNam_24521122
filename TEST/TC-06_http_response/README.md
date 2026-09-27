# TC-06 — HTTP response

## Purpose

The parser must parse an HTTP response: the status code and the headers.

## Input

`input.pcap` is a copy of `tests/fixtures/http_response.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

The file holds one TCP segment, PSH/ACK, from the server 10.0.0.2:80 to the client 10.0.0.1:40000. Its payload is 84 bytes:

```text
HTTP/1.1 200 OK
Content-Type: text/plain
Server: NT204
Content-Length: 5

hello
```

Every header line ends with CRLF. An empty line closes the header block, and the 5-byte body follows it.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-06_http_response/input.pcap --output TEST/TC-06_http_response/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `app_protocol` is `"HTTP"`, with `detection.method="port+payload"` and `detection.rule="http_response"`. The port hint comes from the source port 80.
- `application.kind` is `"response"`, with version `HTTP/1.1`, `status_code=200`, and `reason="OK"`.
- `application.headers` holds the 3 headers with lower-case names.
- `application.content_length` is 5, `application.body_preview` is `hello`, and `application.body_complete` is `true`.
- The event has `status="ok"`, `application.partial=false`, and no errors.

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `app_protocol` | `HTTP` |
| `detection` | `method="port+payload"`, `confidence="high"`, `rule="http_response"` |
| `application.kind` | `response` |
| `application.version` | `HTTP/1.1` |
| `application.status_code` | 200 |
| `application.reason` | `OK` |
| `application.headers` | `{"content-type": "text/plain", "server": "NT204", "content-length": "5"}` |
| `application.content_type` | `text/plain` |
| `application.content_length` | 5 |
| `application.body_len`, `application.body_preview` | 5, `hello` |
| `application.body_complete` | `true` |
| `application.partial` | `false` |
| `payload_len` | 84 |
| `status`, `errors` | `ok`, `[]` |

The request-only fields (`method`, `target`, `host`) are `null`. A response has no request line, and it has no `Host` header.

Wireshark shows the same response: version `HTTP/1.1`, status code `200`, phrase `OK`, the headers `Content-Type`, `Server`, and `Content-Length`, and the 5-byte body `hello`. Its TCP segment length is 84, equal to `payload_len`.

## Verdict

PASS.
