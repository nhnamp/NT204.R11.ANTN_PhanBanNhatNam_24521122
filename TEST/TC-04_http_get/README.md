# TC-04 — HTTP GET

## Purpose

The parser must parse an HTTP request: the request line and the headers.

## Input

`input.pcap` is a copy of `tests/fixtures/http_get.pcap`. The script `tests/fixtures/build_pcaps.py` generates it with a fixed time.

The file holds one TCP segment, PSH/ACK, from 10.0.0.1:40000 to 10.0.0.2:80. Its payload is 83 bytes:

```text
GET /index.html HTTP/1.1
Host: example.com
User-Agent: NT204/1.0
Accept: */*

```

Every line ends with CRLF, and an empty line closes the header block.

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/TC-04_http_get/input.pcap --output TEST/TC-04_http_get/output.jsonl
```

## Expected result

- The run writes 1 event and exits with code 0.
- `app_protocol` is `"HTTP"`. The payload rule and the port agree: `detection.method="port+payload"`, `detection.rule="http_request"`, `detection.confidence="high"`.
- `application.kind` is `"request"`, with method `GET`, target `/index.html`, and version `HTTP/1.1`.
- `application.headers` holds the 3 headers with lower-case names, and `application.host` is `example.com`.
- The request has no body: `body_len=0` and `content_length=null`.
- The event has `status="ok"`, `application.partial=false`, and no errors.

## Actual result

`output.jsonl` holds 1 event. `console.txt` holds the console summary and the exit code 0.

| Field | Value |
|---|---|
| `app_protocol` | `HTTP` |
| `detection` | `method="port+payload"`, `confidence="high"`, `rule="http_request"` |
| `application.kind` | `request` |
| `application.method` | `GET` |
| `application.target` | `/index.html` |
| `application.version` | `HTTP/1.1` |
| `application.headers` | `{"host": "example.com", "user-agent": "NT204/1.0", "accept": "*/*"}` |
| `application.host` | `example.com` |
| `application.content_length`, `application.content_type` | `null`, `null` |
| `application.body_len`, `application.body_complete` | 0, `true` |
| `application.partial` | `false` |
| `payload_len` | 83 |
| `status`, `errors` | `ok`, `[]` |

The response-only fields (`status_code`, `reason`) are `null`.

Wireshark shows the same request: method `GET`, URI `/index.html`, version `HTTP/1.1`, and the headers `Host`, `User-Agent`, and `Accept`. Its TCP segment length is 83, equal to `payload_len`.

## Retest after Assignment 02

The retest reruns the command of this case with the program of Assignment 02. The base fields are unchanged: every event has the same values and the same key order as in the committed output before the retest. The retest adds ten keys to each event: `payload_hex`, `decode_status`, `decoded`, `preprocess_status`, `processing_action`, `reason`, `normalized`, `flow_id`, `direction`, and `processing_errors`. `console.txt` shows the new summary lines.

New values in this case:

- `decode_status` is `not_applicable` and `decoded` is `[]` for the event, because nothing needs decoding.
- `preprocess_status` is `valid`, `processing_action` is `keep`, and `reason` is `null` for the event.
- The event has the `flow_id` `tcp-5f8ec36d79cc`, and `direction` is `forward`.
- `processing_errors` is `[]`.
- `normalized.host` is `example.com`, `normalized.path` is `/index.html`, and `normalized.headers` has the names `host`, `user-agent`, `accept` in lower case.

The tables above describe the base fields and stay valid. The field `errors` is the parser list of Assignment 01. The new list `processing_errors` is separate. No Wireshark check is repeated, because no base field changed.

## Verdict

PASS.
