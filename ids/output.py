"""Write one JSON object per line."""

import json
from pathlib import Path
from types import TracebackType

from ids.events import Event

FLUSH_EVERY = 100


class JsonLinesWriter:
    def __init__(self, path: str | Path, flush_every: int = FLUSH_EVERY) -> None:
        self._file = open(path, "w", encoding="utf-8")
        self._flush_every = flush_every
        self._unflushed = 0

    def __enter__(self) -> "JsonLinesWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def write(self, record: Event | dict) -> None:
        self._file.write(_encode(record))
        self._unflushed += 1
        if self._unflushed >= self._flush_every:
            self.flush()

    def flush(self) -> None:
        self._file.flush()
        self._unflushed = 0

    def close(self) -> None:
        self._file.close()


def _encode(record: Event | dict) -> str:
    """Build the whole line first, so a bad record never leaves half a line in the file."""
    try:
        data = record.to_dict() if isinstance(record, Event) else record
        line = json.dumps(data, ensure_ascii=False, allow_nan=False)
        # A lone surrogate passes json.dumps but fails the UTF-8 file encoding.
        line.encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError(f"record cannot be written as JSON: {exc}") from exc
    return line + "\n"
