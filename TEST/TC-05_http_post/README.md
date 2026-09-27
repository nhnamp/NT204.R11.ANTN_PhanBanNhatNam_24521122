# TC-05 — HTTP POST

## Purpose

The parser must parse an HTTP request that has a body. The event must hold the body length, the declared content length, and a preview of the body.

## Input

`input.pcap` is a copy of `tests/fixtures/http_post.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

The file holds one TCP segment, PSH/ACK, from 10.0.0.1:40000 to 10.0.0.2:80. Its payload is 122 bytes:

```text
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

user=nt204
```

Every header line ends with CRLF. An empty line closes the header block, and the 10-byte form body follows it.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-05_http_post/input.pcap --output TEST/TC-05_http_post/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `app_protocol` is `"HTTP"`, with `detection.method="port+payload"` and `detection.rule="http_request"`.
- `application.kind` is `"request"`, with method `POST` and target `/login`.
- `application.content_length` is 10, and `application.content_type` is `application/x-www-form-urlencoded`.
- `application.body_len` is 10, `application.body_preview` is `user=nt204`, and `application.body_complete` is `true`.
- The event has `status="ok"`, `application.partial=false`, and no errors.

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `app_protocol` | `HTTP` |
| `detection` | `method="port+payload"`, `confidence="high"`, `rule="http_request"` |
| `application.kind` | `request` |
| `application.method`, `application.target`, `application.version` | `POST`, `/login`, `HTTP/1.1` |
| `application.headers` | `{"host": "example.com", "content-type": "application/x-www-form-urlencoded", "content-length": "10"}` |
| `application.host` | `example.com` |
| `application.content_length` | 10 |
| `application.content_type` | `application/x-www-form-urlencoded` |
| `application.body_len` | 10 |
| `application.body_preview` | `user=nt204` |
| `application.body_complete` | `true` |
| `application.partial` | `false` |
| `payload_len` | 122 |
| `status`, `errors` | `ok`, `[]` |

`application.content_length` is an integer. `application.headers["content-length"]` keeps the raw header text `"10"`.

`body_complete` is `true` because `body_len` (10) is equal to `content_length` (10).

`payload_preview` holds the first 64 bytes of the whole TCP payload, so it ends inside the headers. The body is in `application.body_preview`.

Wireshark shows the same request: method `POST`, URI `/login`, the three headers, `Content-Length: 10`, and a 10-byte body. It decodes the body as the form item `user` = `nt204`, equal to `body_preview`. Its TCP segment length is 122, equal to `payload_len`.

## Verdict

PASS.
