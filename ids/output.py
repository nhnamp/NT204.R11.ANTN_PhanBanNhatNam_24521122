"""Write normalized events to a JSON Lines file."""

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

    def write(self, event: Event) -> None:
        self._file.write(json.dumps(event.to_dict(), ensure_ascii=False))
        self._file.write("\n")
        self._unflushed += 1
        if self._unflushed >= self._flush_every:
            self.flush()

    def flush(self) -> None:
        self._file.flush()
        self._unflushed = 0

    def close(self) -> None:
        self._file.close()
