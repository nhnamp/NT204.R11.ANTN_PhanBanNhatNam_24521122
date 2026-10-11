"""Read JSON Lines records from a file, and turn every bad line into a marked record."""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from ids.output import encode_line

MAX_LINE_BYTES = 1_048_576
DISCARD_CHUNK_BYTES = 65_536
UTF8_BOM = b"\xef\xbb\xbf"


class _InvalidLine(Exception):
    pass


class EventFileSource:
    def __init__(self, path: str | Path, max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._path = Path(path)
        self._max_line_bytes = max_line_bytes

    def describe(self) -> str:
        return f"events:{self._path}"

    def __iter__(self) -> Iterator[tuple[dict, list[dict]]]:
        with open(self._path, "rb") as file:
            line_no = 0
            while True:
                # Two extra bytes let a line of exactly the limit end with CRLF and still fit.
                chunk = file.readline(self._max_line_bytes + 2)
                if not chunk:
                    return
                line_no += 1
                try:
                    content = self._content(file, chunk)
                    if line_no == 1:
                        # A byte order mark (Windows Notepad adds one) is legal at the start of the file only.
                        content = content.removeprefix(UTF8_BOM)
                    if not content.strip():
                        continue
                    record = _parse(content)
                except _InvalidLine as exc:
                    error = {"stage": "input", "type": "invalid_record", "message": str(exc)}
                    yield {"source": f"{self.describe()}:{line_no}"}, [error]
                else:
                    yield record, []

    def _content(self, file: BinaryIO, chunk: bytes) -> bytes:
        """Return the line without its line end, and skip the rest of a line that is too long."""
        if not chunk.endswith(b"\n") and len(chunk) == self._max_line_bytes + 2:
            while chunk and not chunk.endswith(b"\n"):
                chunk = file.readline(DISCARD_CHUNK_BYTES)
            raise _InvalidLine(f"line is longer than {self._max_line_bytes} bytes")
        content = chunk.removesuffix(b"\n").removesuffix(b"\r")
        if len(content) > self._max_line_bytes:
            raise _InvalidLine(f"line is longer than {self._max_line_bytes} bytes")
        return content


def _parse(content: bytes) -> dict:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _InvalidLine("line is not valid UTF-8") from exc
    try:
        record = json.loads(text, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise _InvalidLine("JSON is nested too deeply") from exc
    except ValueError as exc:
        raise _InvalidLine(f"line is not valid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise _InvalidLine("top-level value is not an object")
    try:
        encode_line(record)
    except ValueError as exc:
        raise _InvalidLine(str(exc)) from exc
    return record


def _reject_constant(name: str) -> None:
    raise ValueError(f"{name} is not allowed")
