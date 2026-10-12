# A2-T02 — HTML entity decode

## Purpose

The Decoder must decode an HTML entity in the text body of an HTTP message (`DEC-3`). It must replace only an entity that ends with `;`. A body with an entity without `;` must stay unchanged and must give no decoded item. A body without a content type is a text body and is decoded.

## Input

`input.pcap` is a copy of `tests/fixtures/http_entity.pcap`. It holds three TCP packets between `10.0.0.1:40000` and `10.0.0.2:80`.

| Packet | Direction | Frame length (bytes) | Payload (bytes) | HTTP message |
|---|---|---|---|---|
| 1 | 10.0.0.2:80 → 10.0.0.1:40000 | 155 | 101 | Response `200 OK`, `Content-Type: text/html`, body `&lt;script&gt;alert(1)&lt;/script&gt;` |
| 2 | 10.0.0.1:40000 → 10.0.0.2:80 | 149 | 95 | `POST /note`, `Content-Type: text/plain`, body `a=1&lt=2` |
| 3 | 10.0.0.2:80 → 10.0.0.1:40000 | 101 | 47 | Response `200 OK`, no `Content-Type`, body `&lt;b&gt;` |

## Command

Run the command from the repository root.

```bash
python main.py --pcap TEST/A2-T02_html_entity/input.pcap --output TEST/A2-T02_html_entity/output.jsonl
```

The run also writes `flows.jsonl` in the current directory. That file is not part of the evidence.

## Expected result

The expected values follow from the decode rule: `&lt;` becomes `<`, `&gt;` becomes `>`, and an entity without `;` stays as it is.

| Packet | Item `field` | Expected `value` | `methods` | `decode_status` of the event |
|---|---|---|---|---|
| 1 | `http.body` | `<script>alert(1)</script>` | `html_entity` | `ok` |
| 2 | none | no item, because `&lt=2` has no `;` | none | `not_applicable` |
| 3 | `http.body` | `<b>` | `html_entity` | `ok` |

Limit of this check: a `text/plain` body is a text body, so the missing `;` is the only reason for the empty result of packet 2. This case does not test a body of a type that is not text.

Other fields:
- The run writes 3 events and exits with code 0.
- All 3 events have the same `flow_id`. The directions are `forward`, `backward`, `forward`, because the first packet of the flow comes from `10.0.0.2:80`.

## Actual result

`output.jsonl` holds 3 events, and `console.txt` holds the console summary and the exit code 0. The items equal the Expected result table. All events have `status="ok"`, `app_protocol="HTTP"`, `preprocess_status="valid"`, and `processing_action="keep"`.

| Packet | `direction` | Decoded `value` | `methods` | `decode_status` |
|---|---|---|---|---|
| 1 | `forward` | `<script>alert(1)</script>` | `html_entity` | `ok` |
| 2 | `backward` | no item (`decoded` is `[]`) | none | `not_applicable` |
| 3 | `forward` | `<b>` | `html_entity` | `ok` |

The flow id of all events is `tcp-cc207a7df611`.

## Wireshark check

The packets of `input.pcap` were verified in Wireshark (the graphical program and its command-line tool tshark). The check compares the packet list and the packet bytes with the events, one packet at a time. The graphical packet bytes pane crops the last hex column, so tshark gives the exact bytes for the comparison. The three packets share one 5-tuple and have unrelated sequence numbers. The Follow TCP Stream view therefore shows the 101 and 95 bytes of packets 1 and 2 and 46 of the 47 bytes of packet 3. The packet list and the packet bytes are the evidence.

| Packet | Wireshark source → destination | Wireshark Info | Wireshark length | Wireshark TCP payload (bytes) | `length` of the event | `payload_len` of the event | Payload bytes equal | Match |
|---|---|---|---|---|---|---|---|---|
| 1 | 10.0.0.2:80 → 10.0.0.1:40000 | HTTP/1.1 200 OK (text/html) | 155 | 101 | 155 | 101 | yes | yes |
| 2 | 10.0.0.1:40000 → 10.0.0.2:80 | POST /note HTTP/1.1 (text/plain) | 149 | 95 | 149 | 95 | yes | yes |
| 3 | 10.0.0.2:80 → 10.0.0.1:40000 | HTTP/1.1 200 OK | 101 | 47 | 101 | 47 | yes | yes |

Wireshark shows the content types `text/html` and `text/plain` for packets 1 and 2, and none for packet 3. These types are the input of the decode rule.

## Verdict

PASS. The `text/html` body and the body without a content type are decoded. The body with `&lt=2` stays unchanged and gives no item. The packets and the payload bytes equal the Wireshark values.
