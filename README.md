# NT204.R11.ANTN_PhanBanNhatNam_24521122

This repository holds the coursework for the course *Intrusion Detection and Prevention Systems* (NT204) at UIT. The project is a simple Intrusion Detection System (IDS) in Python, built across several assignments.

Assignment 01 builds the **packet capture and parser module**. The module reads packets from a live network interface or from a PCAP file, parses them, and writes one normalized event per packet as JSON Lines. The detection engine of the later assignments reads only these events. It never reads a Scapy packet.

## Contents

1. [Overview and scope](#1-overview-and-scope)
2. [Installation](#2-installation)
3. [Usage](#3-usage)
4. [Architecture](#4-architecture)
5. [Event schema](#5-event-schema)
6. [Application protocol detection](#6-application-protocol-detection)
7. [Error handling](#7-error-handling)
8. [Tests](#8-tests)
9. [Limitations](#9-limitations)
10. [AI usage disclosure](#10-ai-usage-disclosure)

## 1. Overview and scope

| Layer | Supported protocols |
|---|---|
| Network | IPv4 |
| Transport | TCP, UDP |
| Application | HTTP/1.x, DNS, SMTP |

The module:

- captures packets from a live interface, or reads them from a PCAP or pcapng file, through one shared pipeline;
- parses IPv4, TCP, UDP, HTTP/1.x, DNS, and SMTP;
- detects the application protocol from the payload, and uses the port only as a hint;
- never stops on a malformed, truncated, or unsupported packet;
- writes every event to a JSON Lines file, one event per line.

## 2. Installation

The project is tested with Python 3.14.5, Scapy 2.7.0, and pytest 8.4.2. It needs Python 3.11 or newer. Scapy needs no external binary.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Live capture needs root on macOS and Linux. Run it with the Python of the virtual environment, because `sudo` does not keep the activated environment:

```bash
sudo .venv/bin/python main.py --interface en0
```

To list the interface names on macOS, use `ifconfig -l`. On Linux, use `ip link`.

## 3. Usage

```text
python main.py (--interface IFACE | --pcap FILE) [--output FILE] [--unknown {keep,drop}] [--count N]
```

| Option | Default | Meaning |
|---|---|---|
| `--interface IFACE` | — | Capture live traffic from the interface `IFACE`. |
| `--pcap FILE` | — | Read packets from the PCAP or pcapng file `FILE`. |
| `--output FILE` | `events.jsonl` | Write the events to `FILE`. The run overwrites an existing file. |
| `--unknown {keep,drop}` | `keep` | `keep` writes an unsupported packet as an event with `app_protocol="UNKNOWN"`. `drop` does not write it. |
| `--count N` | no limit | Stop after `N` packets. `N` must be at least 1. |

`--interface` and `--pcap` are mutually exclusive, and one of them is required.

Examples:

```bash
python main.py --pcap tests/fixtures/all.pcap --output events.jsonl
```

```bash
sudo .venv/bin/python main.py --interface en0 --count 100 --output /tmp/live.jsonl
```

```bash
python main.py --pcap tests/fixtures/unknown_protocols.pcap --unknown drop
```

At the end of a run, the program prints a summary on stderr. The events go to the output file, so the two streams never mix.

```text
packets read: 5
events written: 1
ok: 1
partial: 0
unsupported: 0
malformed: 0
dropped: 4
elapsed: 0.001s
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | The run finished, or Ctrl-C stopped it. Ctrl-C closes the output file and prints the summary. |
| 1 | A file cannot be opened, live capture has no root permission, or the interface does not exist. The program prints one error line and no traceback. |
| 2 | The command line is not valid. |

## 4. Architecture

```text
 Live capture (--interface)        PCAP import (--pcap)
 LiveSource: sniff in a thread     PcapSource: PcapReader, one packet at a time
            └──────────────┬───────────────┘
                           ▼   the same loop in cli.run, one call site
                 Pipeline.process(packet)
                   ├─ parse_ipv4            → event.network
                   ├─ parse_transport       → event.transport, payload
                   ├─ detect_app_protocol   → event.app_protocol, event.detection
                   ├─ parse_http / parse_dns / parse_smtp → event.application
                   └─ errors and status     → event.errors, event.status
                           ▼
                 JsonLinesWriter.write(event)  → one line in the output file
```

| Module | Role |
|---|---|
| `main.py` | Entry point. It parses the arguments and calls `ids.cli.run`. |
| `ids/cli.py` | Selects the packet source, runs the capture loop, and prints the summary. |
| `ids/capture/base.py` | `PacketSource`: the interface that both sources implement. |
| `ids/capture/pcap.py` | `PcapSource`: reads a capture file as a stream, so a large file never loads into memory. |
| `ids/capture/live.py` | `LiveSource`: runs Scapy `sniff` in a thread and hands each packet to the loop through a queue. |
| `ids/pipeline.py` | Runs the stages in order. It wraps each stage, so a failure keeps the layers that are already parsed. |
| `ids/parsers/network.py` | Parses the IPv4 header (RFC 791). |
| `ids/parsers/transport.py` | Parses the TCP header (RFC 793) or the UDP header (RFC 768), and extracts the payload. |
| `ids/parsers/detector.py` | The Application Protocol Detector. |
| `ids/parsers/http.py` | Parses an HTTP/1.x request or response (RFC 7230). |
| `ids/parsers/dns.py` | Reads DNS names with pointer safety, and parses a DNS message (RFC 1035). |
| `ids/parsers/smtp.py` | Parses SMTP commands, replies, and data lines (RFC 5321). |
| `ids/events.py` | The event dataclasses and their conversion to JSON-compatible values. |
| `ids/output.py` | `JsonLinesWriter`: writes one event per line. |

Two design rules hold the architecture together:

- **One pipeline.** Live capture and PCAP import share every stage after the source. Only `cli.run` calls `Pipeline.process`.
- **One library boundary.** Only `ids/capture/` and `ids/parsers/` import Scapy. An event holds JSON-compatible values only, so the detection engine never needs Scapy.

## 5. Event schema

Every line of the output file is one JSON object: one event for one captured packet. A field that a layer does not have is `null`.

### Event

| Field | Type | Meaning |
|---|---|---|
| `packet_id` | int | 1-based counter of the packets read in the run. A dropped packet still takes an id, so a gap in the ids shows a dropped packet. |
| `timestamp` | float | Capture time in epoch seconds. |
| `timestamp_iso` | string | The same time in ISO 8601, always UTC. |
| `source` | string | `"pcap:<file>"` or `"live:<interface>"`. |
| `length` | int | Captured length of the packet in bytes. |
| `link_type` | string | `Ethernet`, `Loopback`, `LinuxSLL`, `RawIP`, or the Scapy class name. |
| `network` | object or null | IPv4 fields. `null` when the packet is not IPv4. |
| `transport` | object or null | TCP or UDP fields. `null` when the packet has no supported transport. |
| `app_protocol` | string | `HTTP`, `DNS`, `SMTP`, or `UNKNOWN`. |
| `detection` | object | How the application protocol was decided. |
| `application` | object or null | Protocol-specific fields. `null` when no application parser ran. |
| `payload_len` | int | Length of the application payload in bytes, 0 when there is none. |
| `payload_preview` | string | The first 64 payload bytes as lower-case hex, `""` when there is no payload. |
| `status` | string | `ok`, `partial`, `unsupported`, or `malformed` (see [section 7](#7-error-handling)). |
| `errors` | list | One entry per fault: `{"stage", "type", "message"}`. Empty when there is no fault. |

### `network` (IPv4)

| Field | Type | Meaning |
|---|---|---|
| `protocol` | string | Always `IPv4`. |
| `src_ip`, `dst_ip` | string | Source and destination address. |
| `version` | int | The version field of the header. |
| `header_len` | int | Header length in bytes (IHL × 4). |
| `dscp` | int | Differentiated Services Code Point: the high 6 bits of byte 1. |
| `total_len` | int | Total length of the datagram in bytes. |
| `identification` | int | Identification field. |
| `flags` | list of string | `DF` and `MF` when they are set. |
| `frag_offset` | int | Fragment offset **in bytes**. The header counts 8-byte units, and the parser multiplies the value by 8. |
| `ttl` | int | Time to live. |
| `proto_number` | int | IP protocol number. |
| `proto_name` | string | `ICMP`, `TCP`, `UDP`, or the number as a string. |
| `checksum` | int | Header checksum. |
| `has_options` | bool | True when the header has options. |

### `transport` (TCP or UDP)

| Field | Type | Protocol | Meaning |
|---|---|---|---|
| `protocol` | string | both | `TCP` or `UDP`. |
| `src_port`, `dst_port` | int | both | Source and destination port. |
| `payload_len` | int | both | Payload length in bytes. |
| `checksum` | int | both | Header checksum. |
| `length` | int or null | UDP | Length field: header plus payload. |
| `seq`, `ack` | int or null | TCP | Absolute sequence and acknowledgment number. |
| `data_offset` | int or null | TCP | Header length in 32-bit words. |
| `flags` | list of string | TCP | Names of the set flags: `FIN SYN RST PSH ACK URG ECE CWR`. |
| `flags_raw` | int or null | TCP | The flag byte as a number. |
| `flags_str` | string or null | TCP | Scapy notation, for example `SA`. |
| `window` | int or null | TCP | Window size. |
| `urgent_ptr` | int or null | TCP | Urgent pointer. |
| `options` | list | TCP | `[name, value]` for MSS, WScale, SAckOK, Timestamp, and NOP. A tuple value becomes a list, and a bytes value becomes hex. Other options keep the name only. |
| `handshake` | string or null | TCP | `SYN`, `SYN/ACK`, or `ACK` when the packet is one step of a handshake. |

`handshake` is `ACK` only for an ACK without SYN, FIN, or RST, and with no payload.

### `detection`

| Field | Type | Meaning |
|---|---|---|
| `protocol` | string | The same value as `app_protocol`. |
| `method` | string | `payload`: a payload rule matched. `port+payload`: a rule matched and the port hint agrees. `port`: only the port hint decided, because the payload is empty. `none`: nothing decided. |
| `confidence` | string | `high` when a payload rule matched, `low` otherwise. |
| `rule` | string | The payload rule that matched, `port_hint`, or `""`. |

### `application` (HTTP)

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | `request` or `response`. |
| `version` | string | For example `HTTP/1.1`. |
| `method`, `target` | string or null | Request only. |
| `status_code`, `reason` | int or string or null | Response only. |
| `headers` | object | Header names in lower case. A repeated header becomes a list. |
| `host` | string or null | The `Host` header. |
| `content_length` | int or null | The `Content-Length` header as a number. `null` when it is absent or not a decimal number. |
| `content_type` | string or null | The `Content-Type` header. |
| `body_len` | int | Body bytes in this packet. |
| `body_preview` | string | The first 256 body bytes, decoded as UTF-8 with replacement characters. |
| `body_complete` | bool | True when `body_len` is at least `content_length`. True when there is no `Content-Length`. |
| `partial` | bool | True when the header block has no closing empty line. |

### `application` (DNS)

| Field | Type | Meaning |
|---|---|---|
| `transaction_id` | int | Message ID. |
| `is_response` | bool | The QR bit. |
| `opcode` | int | Operation code. |
| `flags` | list of string | `AA`, `TC`, `RD`, and `RA` when they are set. |
| `rcode`, `rcode_name` | int, string | Response code, for example `0` and `NOERROR`. |
| `qdcount`, `ancount`, `nscount`, `arcount` | int | Section counts from the header. The authority and additional sections are counted, not parsed. |
| `questions` | list | `{name, qtype, qtype_name, qclass}` for each question. |
| `answers` | list | `{name, type, type_name, rclass, ttl, rdata}` for each answer record. |
| `partial` | bool | True when the parser stopped before the end of the message. |

`rdata` depends on the record type:

- A and AAAA: the address as a string.
- CNAME, NS, and PTR: a name.
- MX: `{preference, exchange}`.
- TXT: a list of strings.
- SOA: `{mname, rname, serial, refresh, retry, expire, minimum}`.
- Any other type: `{"raw_hex": ...}`.

An answer uses `rclass`, not `class`, because `class` is a Python keyword. The root name is `""`.

### `application` (SMTP)

| Field | Type | Meaning |
|---|---|---|
| `kind` | string | The kind of the first line: `command`, `response`, or `data`. |
| `lines` | list | One entry per line of the payload. |
| `multiline` | bool | True when a reply line uses the `-` separator. |
| `partial` | bool | True when the last line has no line end. |

Every entry in `lines` has `kind` and the decoded `text`. A command line adds `command` and `argument`, for example `MAIL FROM` and `<alice@example.com>`. A reply line adds `code`, `separator`, and `message`.

### Example

This event comes from `TEST/TC-04_http_get/output.jsonl`. The file holds it on one line. It is formatted here for reading, and `payload_preview` is shortened.

```json
{
  "packet_id": 1,
  "timestamp": 1758441600.0,
  "timestamp_iso": "2025-09-21T08:00:00+00:00",
  "source": "pcap:TEST/TC-04_http_get/input.pcap",
  "length": 137,
  "link_type": "Ethernet",
  "network": {"protocol": "IPv4", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "version": 4,
              "header_len": 20, "dscp": 0, "total_len": 123, "identification": 1, "flags": [],
              "frag_offset": 0, "ttl": 64, "proto_number": 6, "proto_name": "TCP",
              "checksum": 26234, "has_options": false},
  "transport": {"protocol": "TCP", "src_port": 40000, "dst_port": 80, "payload_len": 83,
                "checksum": 61834, "length": null, "seq": 1001, "ack": 0, "data_offset": 5,
                "flags": ["PSH", "ACK"], "flags_raw": 24, "flags_str": "PA", "window": 8192,
                "urgent_ptr": 0, "options": [], "handshake": null},
  "app_protocol": "HTTP",
  "detection": {"protocol": "HTTP", "method": "port+payload", "confidence": "high",
                "rule": "http_request"},
  "application": {"kind": "request", "version": "HTTP/1.1",
                  "headers": {"host": "example.com", "user-agent": "NT204/1.0", "accept": "*/*"},
                  "body_len": 0, "body_preview": "", "body_complete": true, "partial": false,
                  "method": "GET", "target": "/index.html", "host": "example.com",
                  "status_code": null, "reason": null, "content_length": null,
                  "content_type": null},
  "payload_len": 83,
  "payload_preview": "474554202f696e6465782e68746d6c20…",
  "status": "ok",
  "errors": []
}
```

## 6. Application protocol detection

The detector does not trust the port alone (`DET-1`). It runs the payload rules first, and uses the port only as a hint.

### Payload rules

The rules run in this order, and the first match wins:

| Order | Rule | Matches when |
|---|---|---|
| 1 | `http_request` | The first line is `METHOD target HTTP/1.x`. The method is one of `GET POST PUT DELETE HEAD OPTIONS PATCH TRACE CONNECT`. A version cut at the segment end is accepted. |
| 2 | `http_response` | The first line starts with `HTTP/1.0` or `HTTP/1.1`, a space, and 3 digits. |
| 3 | `smtp_response` | The line starts with a reply code (first digit 2 to 5), then a space or `-`. Without an SMTP port hint, the text must also be printable ASCII that ends with CRLF. |
| 4 | `smtp_command` | The first token is an SMTP command, in any case. `MAIL` must be followed by `FROM:`, and `RCPT` by `TO:`. |
| 5 | `dns_udp` | The payload has a 12-byte header with a plausible opcode, a zero Z bit, 1 to 16 questions, and at most 64 records per section. The first question name parses within bounds, with a non-zero type and class. |
| 5 | `dns_tcp` | The 2-byte length prefix is equal to the remaining length, and the rest passes the `dns_udp` rule. |

The text rules run first, because they are cheap and specific. The DNS rule runs last, because random binary data can pass a structural check by chance.

### Port hints

| Ports | Hint |
|---|---|
| 80, 8080, 8000, 8888 | HTTP |
| 53, 5353 | DNS |
| 25, 587, 2525 | SMTP |

The detector checks the destination port first, then the source port, so a reply from a server also gets a hint.

The hint decides the protocol only when the payload is empty, for example on a SYN or a pure ACK. The result is then `method="port"` and `confidence="low"`, and no application parser runs. A non-empty payload that matches no rule is `UNKNOWN`, even on a hinted port.

### Detection on non-standard ports

The bonus cases in `TEST/` prove the detector on ports outside the hint table, and against misleading ports. Each case was also opened in Wireshark with its default settings.

| Case | Traffic | Wireshark (default settings) | This parser |
|---|---|---|---|
| [BONUS-01](TEST/BONUS-01_http_nonstandard_port/) | HTTP on 8080 | HTTP | HTTP, `port+payload` |
| [BONUS-01](TEST/BONUS-01_http_nonstandard_port/) | HTTP on 3000 | TCP only | HTTP, `payload` |
| [BONUS-02](TEST/BONUS-02_dns_nonstandard_port/) | DNS over UDP on 1053 | DNS | DNS, `payload` |
| [BONUS-02](TEST/BONUS-02_dns_nonstandard_port/) | DNS over TCP on 9053 | TCP only | DNS, `payload` |
| [BONUS-03](TEST/BONUS-03_smtp_nonstandard_port/) | SMTP on 2526 | TCP only | SMTP, `payload` |
| [BONUS-04](TEST/BONUS-04_detection_traps/) | Random bytes on TCP 80 | TCP | `UNKNOWN` |
| [BONUS-04](TEST/BONUS-04_detection_traps/) | Random bytes on UDP 53 | DNS | `UNKNOWN` |
| [BONUS-04](TEST/BONUS-04_detection_traps/) | Random bytes on TCP 25 | SMTP | `UNKNOWN` |
| [BONUS-04](TEST/BONUS-04_detection_traps/) | HTTP request on TCP 53 | TCP only | HTTP, `payload` |

The parser gives the correct protocol in all 9 cases. Wireshark relies on its port table in several of them, so it misses traffic on an unexpected port and labels random bytes by the port.

## 7. Error handling

The program never stops on a bad packet (`ERR-1`). The test case [TC-12](TEST/TC-12_malformed_packet/) runs a corpus of 20 kinds of bad input, and a fuzz test mutates every fixture packet 200 times.

### Stage contract

`Pipeline.process` runs each stage in its own guard:

- A parser reports a fault that it checks for as a typed error: `truncated`, `malformed`, `limit`, or `fragment`.
- An unexpected exception in a stage becomes an error with the exception class name as its type. The stages after it do not run, and the layers before it stay in the event.
- A fault in one layer never removes a lower layer. For example, an IPv4 header with a bad length keeps its addresses in `network`.

### Status values

| `status` | Meaning | Kept by `--unknown drop` |
|---|---|---|
| `ok` | Every present layer parsed. `app_protocol` can still be `UNKNOWN`: TCP and UDP are supported, and only the application is unknown. | yes |
| `partial` | The packet is cut, fragmented, or over a parser limit. The event holds what was readable. | yes |
| `unsupported` | No supported network or transport layer: for example ARP, IPv6, ICMP, or GRE. | no |
| `malformed` | A header or a message breaks its protocol rules. | yes |

### Error entries

Each entry in `errors` has three fields:

- `stage`: `network`, `transport`, `http`, `dns`, `smtp`, `detector`, or `pipeline`.
- `type`: `truncated`, `malformed`, `limit`, `fragment`, or an exception class name.
- `message`: a short description.

A non-first IPv4 fragment is `partial` with a `fragment` error. The program does not reassemble fragments.

### Limits

The limits keep the cost of one crafted packet small.

| Parser | Limit | Result when exceeded |
|---|---|---|
| HTTP | 100 header lines and 8 KB of headers | `limit` error, `status="partial"` |
| DNS | 64 records per section | `limit` error, `status="partial"` |
| DNS names | 63-byte labels, 255-byte names, 64 compression jumps, backward pointers only | `malformed` error |
| SMTP | 1 000 lines per payload | `limit` error, `status="partial"` |
| Output | flush every 100 events | at most 100 events lost if the process is killed |

## 8. Tests

Run the unit tests:

```bash
pytest
```

The suite has 219 tests. It covers every parser, the detector, the pipeline, the CLI, the bad-input corpus, the non-standard ports, and a seeded fuzz test.

The fixtures in `tests/fixtures/` are generated. Regenerate them with one command:

```bash
python tests/fixtures/build_pcaps.py
```

The script writes every fixture with fixed times and fixed random seeds, so the files are identical on every run. `all.pcap` holds every fixture packet, and `malformed/` holds the corpus of R9.2.

### Test cases

The graded evidence is in [`TEST/`](TEST/). Each case has a folder with the input, the output, the console summary, and a README that states the purpose, the command, the expected result, the actual result, and the verdict. The case README also records the comparison with Wireshark. The commit of each case is in the index of [`TEST/README.md`](TEST/README.md).

| ID | Case | Result |
|---|---|---|
| TC-01 | TCP handshake: SYN, SYN/ACK, ACK | PASS |
| TC-02 | TCP packet with a payload | PASS |
| TC-03 | UDP packet | PASS |
| TC-04 | HTTP GET request | PASS |
| TC-05 | HTTP POST request with a body | PASS |
| TC-06 | HTTP response: status code and headers | PASS |
| TC-07 | DNS query: domain and query type | PASS |
| TC-08 | DNS response with one answer | PASS |
| TC-09 | SMTP commands: EHLO, MAIL FROM, RCPT TO | PASS |
| TC-10 | SMTP responses, including a multi-line reply | PASS |
| TC-11 | Unknown protocols, with `keep` and `drop` | PASS |
| TC-12 | Malformed packets: the 20-item corpus | PASS |
| BONUS-01 | HTTP on a non-standard port | PASS |
| BONUS-02 | DNS on a non-standard port | PASS |
| BONUS-03 | SMTP on a non-standard port | PASS |
| BONUS-04 | Detection traps | PASS |

To check the evidence, run the command in each case README and compare the new output with the committed `output.jsonl`. Only the `source` field can differ. `console.txt` shows the summary format of its phase, so do not compare it.

## 9. Limitations

- **IPv4 only.** IPv6 and other network protocols are `unsupported`.
- **No TCP stream reassembly.** The pipeline parses one packet at a time. An HTTP or SMTP message that spans several segments is parsed segment by segment. A segment that carries only an HTTP body or SMTP message content matches no rule, so it is `UNKNOWN`.
- **No IP fragment reassembly.** A non-first fragment is `partial`, with no transport data.
- **No SMTP session state.** The parser classifies each line alone. A body line that looks like a command or a reply is classified as one.
- **HTTP line ends.** The HTTP parser splits on CRLF only. A hand-typed request with bare LF line ends is detected as HTTP, but its fields are parsed wrongly.
- **DNS edge cases.** An mDNS announcement with no question is `UNKNOWN`. A label that contains a dot is shown as two labels.
- **Empty frames.** An empty or 1-byte frame is `unsupported` with no error, so `--unknown drop` removes it.
- **Credentials in the output.** An SMTP `AUTH` argument or an HTTP header can hold credentials, and the event log stores them. Check the output of a live capture before you share it.
- **Live capture.** A run without root overwrites the output file with an empty file before it reports the permission error. On an idle interface, Ctrl-C takes up to 1 second to stop the capture thread.
- **Output file.** Every run overwrites the output file.
- **Malformed event time.** When the outer guard of the pipeline catches an exception, the event has `timestamp=0.0` (1970-01-01) and `status="malformed"`.

## 10. AI usage disclosure

This project uses Claude models from Anthropic, through the Claude Code harness.

Claude Fable 5.1 helped to discuss the scope of the assignment and to decide the development plan.

Claude Opus 5.5 helped to find bugs after the code was written, to run and write unit tests, and to write docstrings and documents, including this README and the test case reports in `TEST/`.

Some bugs that the review found, and their causes:

| Area | Bug | Cause |
|---|---|---|
| Live capture | Without `--count`, the capture stopped after the first packet. | `count=None` was passed to Scapy `sniff`. Scapy compares `0 < count`, and the `TypeError` closed the socket. Scapy uses `0` for no limit. |
| Event output | The plan assumed that `packet.time` is a `float`, so every packet read from a PCAP file would fail JSON conversion. The review found this before the pipeline code was written. | `PcapReader` gives `packet.time` as `EDecimal`, a `Decimal` subclass, not `float`. |
| TCP parser | A pure ACK from a real network was not a handshake step. | Ethernet pads a short frame to 60 bytes, and the parser counted the padding as payload. |
| Transport parser | A VXLAN packet was reported as the inner TCP flow. | `getlayer(TCP)` searches every layer. The parser now reads only the layer after the outer IP header. |
| DNS detection | Most real DNS traffic was `UNKNOWN`. | The rule treated bits 4 to 6 of the flags as the Z bit. Bits 4 and 5 are the DNSSEC flags CD and AD, and `dig` sets AD by default. |
| Pipeline | With `--unknown drop`, a TCP SYN to an unlisted port was dropped. | Detection changed `status` to `unsupported` when the application was unknown. A port scan detector needs these packets. |
| HTTP parser | One header byte `0xB2` removed all IP and TCP fields from the event. | ISO-8859-1 decodes `0xB2` to `²`. `str.isdigit()` accepts it, but `int()` raises. |
| SMTP parser | A data line such as `12345 records` became a reply with code 123. | The rule checked only the first 3 digits. RFC 5321 also requires a space, a hyphen, or the line end after the code. |
| Fuzz test | The test could never fail. | The outer guard of the pipeline turns every exception into an event. The test now also rejects any error that comes from an unexpected exception. |
