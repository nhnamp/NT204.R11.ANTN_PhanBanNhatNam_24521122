# A2-T01 — HTTP URL decode

## Purpose

The Decoder must decode the percent escapes of an HTTP target and of a form body (`DEC-2`). It must keep a `+` in the path and turn a `+` in the query or in a form body into a space. It must mark an invalid escape as `partial` and must not stop the run.

## Input

`input.pcap` is a copy of `tests/fixtures/http_percent.pcap`. It holds four TCP packets with one HTTP message each. All packets go from `10.0.0.1:40000` to `10.0.0.2:80`.

| Packet | Frame length (bytes) | Payload (bytes) | HTTP message |
|---|---|---|---|
| 1 | 116 | 62 | `GET /search?q=%27%20OR%201%3D1` |
| 2 | 104 | 50 | `GET /a+b?c+d=e%2Bf` |
| 3 | 194 | 140 | `POST /login`, `Content-Type: application/x-www-form-urlencoded`, `Content-Length: 28`, body `user=%27+OR+1%3D1&note=a%2Bb` |
| 4 | 98 | 44 | `GET /p?q=%zz` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T01_http_url_decode/input.pcap --output TEST/A2-T01_http_url_decode/output.jsonl
```

The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

## Expected result

The expected values follow from the decode rules, not from the program. A hand calculation with the Python functions `urllib.parse.unquote` and `unquote_plus` gives the same values.

| Packet | Item `field` | Expected `value` | `methods` | Item `status` | `decode_status` of the event |
|---|---|---|---|---|---|
| 1 | `http.target` | `/search?q=' OR 1=1` | `form` | `ok` | `ok` |
| 2 | `http.target` | `/a+b?c d=e+f` | `form` | `ok` | `ok` |
| 3 | `http.body` | `user=' OR 1=1&note=a+b` | `form` | `ok` | `ok` |
| 4 | `http.target` | `/p?q=%zz` (raw value) | none | `partial`, reason `invalid percent escape` | `partial` |

Other fields:
- The run writes 4 events and exits with code 0.
- The field `application.target` keeps the raw target in every event.
- All 4 events have the same `flow_id` and the direction `forward`.
- No event has `processing_errors`.

## Actual result

`output.jsonl` holds 4 events, and `console.txt` holds the console summary and the exit code 0. The items equal the Expected result table. All events have `status="ok"`, `app_protocol="HTTP"`, `preprocess_status="valid"`, and `processing_action="keep"`.

| Packet | `application.target` | Decoded `value` | `decode_status` |
|---|---|---|---|
| 1 | `/search?q=%27%20OR%201%3D1` | `/search?q=' OR 1=1` | `ok` |
| 2 | `/a+b?c+d=e%2Bf` | `/a+b?c d=e+f` | `ok` |
| 3 | `/login` | `user=' OR 1=1&note=a+b` (`http.body`) | `ok` |
| 4 | `/p?q=%zz` | `/p?q=%zz`, reason `invalid percent escape` | `partial` |

The flow id of all events is `tcp-5f8ec36d79cc`.

## Wireshark check

The packets of `input.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison. The four packets share one 5-tuple and have unrelated sequence numbers. The Follow TCP Stream view therefore shows only the 62 bytes of packet 1. Wireshark marks packets 2 and 3 as `[TCP Previous segment not captured]` and packet 4 as `[TCP Retransmission]`. This does not change the packet bytes, so the packet list and the packet bytes are the evidence.

| Packet | Wireshark source → destination | Wireshark length | Wireshark TCP payload (bytes) | `length` of the event | `payload_len` of the event | Payload bytes equal | Match |
|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.1:40000 → 10.0.0.2:80 | 116 | 62 | 116 | 62 | yes | yes |
| 2 | 10.0.0.1:40000 → 10.0.0.2:80 | 104 | 50 | 104 | 50 | yes | yes |
| 3 | 10.0.0.1:40000 → 10.0.0.2:80 | 194 | 140 | 194 | 140 | yes | yes |
| 4 | 10.0.0.1:40000 → 10.0.0.2:80 | 98 | 44 | 98 | 44 | yes | yes |

The Wireshark Info column of packet 1 shows the raw request line `GET /search?q=%27%20OR%201%3D1 HTTP/1.1`. The raw escapes in the packet bytes are the input of the Decoder. The decoded values in the Expected result table come from these bytes.

## Verdict

PASS. The decoded targets and the decoded form body equal the expected values. The invalid escape in packet 4 gives `partial` with the reason `invalid percent escape`, and the run continues. The packets and the payload bytes equal the Wireshark values.
