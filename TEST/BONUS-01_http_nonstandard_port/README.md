# BONUS-01 — HTTP on a non-standard port

## Purpose

The detector must recognise HTTP on a port other than 80 (`DET-4`). The payload decides the protocol, and the port is only a hint (`DET-1`, R5.2).

## Input

`input/` holds copies of two fixtures from `tests/fixtures/`. The script `tests/fixtures/build_pcaps.py` generates them with fixed times.

| File | Port | In the hint table (R5.4) | Packets |
|---|---|---|---|
| `bonus_http_3000.pcap` | 3000 | no | 1: `POST /bonus` with the form body `user=nt204` |
| `bonus_http_8080.pcap` | 8080 | yes | 2: `GET /bonus` and the response `200 OK` with the body `hello` |

Port 3000 proves the bonus: no hint names it, so only the payload can decide the protocol. Port 8080 shows the common case, a well-known alternate HTTP port, where the hint and the payload agree.

## Commands

Run the commands from the repository root.

```bash
python main.py --pcap TEST/BONUS-01_http_nonstandard_port/input/bonus_http_3000.pcap --output TEST/BONUS-01_http_nonstandard_port/output/bonus_http_3000.jsonl
```

```bash
python main.py --pcap TEST/BONUS-01_http_nonstandard_port/input/bonus_http_8080.pcap --output TEST/BONUS-01_http_nonstandard_port/output/bonus_http_8080.jsonl
```

## Expected result

- Both runs exit with code 0, and every event has `status="ok"` and no errors.
- Port 3000: `app_protocol="HTTP"`, `detection.method="payload"`, `detection.confidence="high"`, `detection.rule="http_request"`.
- Port 8080: `app_protocol="HTTP"`, `detection.method="port+payload"`, `detection.confidence="high"`, with the rules `http_request` and `http_response`.
- The HTTP parser fills `application` on every packet, the same as on port 80.

## Actual result

`output/` holds one JSON Lines file per input. `console.txt` holds both commands, their summaries, and their exit codes.

| File | `packet_id` | Direction | `app_protocol` | `detection.method` | `detection.rule` | `application` |
|---|---|---|---|---|---|---|
| `bonus_http_3000` | 1 | 40000 → **3000** | `HTTP` | **`payload`** | `http_request` | `POST /bonus`, host `example.com`, body `user=nt204` |
| `bonus_http_8080` | 1 | 40000 → 8080 | `HTTP` | `port+payload` | `http_request` | `GET /bonus`, host `example.com` |
| `bonus_http_8080` | 2 | 8080 → 40000 | `HTTP` | `port+payload` | `http_response` | status 200, body `hello` |

Every event has `detection.confidence="high"`, `status="ok"`, and no errors.

`detection.method` shows how the protocol was decided. On port 3000 the value is `payload`, because no hint exists. On port 8080 the value is `port+payload`, because the hint and the payload agree. On port 8080 the response gets the hint from its source port.

Wireshark decodes both packets on port 8080 as HTTP, because 8080 is in its own list of HTTP ports. On port 3000 it shows only TCP. After Decode As is set to HTTP for port 3000, it shows `POST /bonus HTTP/1.1` and the form item `user` = `nt204`, the same as the event. The parser needs no such setting, because the payload decides the protocol.

## Verdict

PASS.
