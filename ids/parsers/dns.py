"""Read DNS names (RFC 1035 section 4.1.4) with bounds and pointer safety.

A name is a sequence of length-prefixed labels, closed by a zero label.
The two high bits of a length octet mark a two-byte pointer to an earlier offset.
"""

MAX_LABEL = 63
MAX_NAME = 255
MAX_JUMPS = 64
POINTER_MASK = 0xC0


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Return the name at offset, and the offset just after the name.

    A violation of the DNS name limits raises ValueError, so a crafted packet
    cannot send the reader out of bounds or into a pointer loop (R7.5).
    """
    if not 0 <= offset < len(data):
        raise ValueError("name starts outside the message")
    labels: list[str] = []
    length = 0
    jumps = 0
    after: int | None = None
    position = offset
    while True:
        if position >= len(data):
            raise ValueError("name runs past the message")
        size = data[position]
        if size & POINTER_MASK == POINTER_MASK:
            if position + 1 >= len(data):
                raise ValueError("compression pointer is cut")
            target = ((size & 0x3F) << 8) | data[position + 1]
            if target >= position:
                raise ValueError("compression pointer does not point backwards")
            jumps += 1
            if jumps > MAX_JUMPS:
                raise ValueError("name uses more than 64 compression jumps")
            if after is None:
                after = position + 2
            position = target
            continue
        if size > MAX_LABEL:
            raise ValueError("label is longer than 63 bytes")
        position += 1
        if size == 0:
            return ".".join(labels), position if after is None else after
        if position + size > len(data):
            raise ValueError("label runs past the message")
        labels.append(data[position : position + size].decode("ascii", errors="replace"))
        position += size
        length += size + 1
        if length + 1 > MAX_NAME:
            raise ValueError("name is longer than 255 bytes")
