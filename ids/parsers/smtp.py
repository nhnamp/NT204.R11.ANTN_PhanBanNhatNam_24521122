"""Parse SMTP commands, responses, and message data (RFC 5321)."""

from ids.events import ParseError, SmtpInfo, SmtpLine

MAX_LINES = 1000
SMTP_COMMANDS = (
    "HELO",
    "EHLO",
    "DATA",
    "RSET",
    "NOOP",
    "QUIT",
    "VRFY",
    "EXPN",
    "HELP",
    "AUTH",
    "STARTTLS",
)
TWO_TOKEN_COMMANDS = {"MAIL": ("FROM:", "MAIL FROM"), "RCPT": ("TO:", "RCPT TO")}


def parse_smtp(payload: bytes) -> tuple[SmtpInfo, list[ParseError]]:
    """Parse every line of one SMTP payload, and keep unknown lines as data."""
    chunks = payload.split(b"\n")
    partial = bool(payload) and not payload.endswith(b"\n")
    if chunks and chunks[-1] == b"":
        chunks.pop()
    errors: list[ParseError] = []
    if len(chunks) > MAX_LINES:
        errors.append(
            ParseError(stage="smtp", type="limit", message="more than 1000 lines")
        )
        chunks = chunks[:MAX_LINES]
    lines = [_line(chunk) for chunk in chunks]
    return SmtpInfo(
        kind=lines[0].kind if lines else "data",
        lines=lines,
        multiline=any(line.separator == "-" for line in lines),
        partial=partial,
    ), errors


def _line(chunk: bytes) -> SmtpLine:
    """Classify one line by grammar, because the port gives only a hint."""
    if chunk.endswith(b"\r"):
        chunk = chunk[:-1]
    text = chunk.decode("ascii", errors="replace")
    # RFC 5321 section 4.2: a reply code starts with 2 to 5 and ends at a space, a hyphen, or the line end.
    code, rest = text[:3], text[3:4]
    if len(code) == 3 and code[0] in "2345" and code.isdecimal() and rest in ("", " ", "-"):
        return SmtpLine(
            kind="response",
            text=text,
            code=int(code),
            separator=rest,
            message=text[4:].strip(),
        )
    command = _command(text)
    if command is not None:
        return SmtpLine(kind="command", text=text, command=command[0], argument=command[1])
    return SmtpLine(kind="data", text=text)


def _command(text: str) -> tuple[str, str] | None:
    token, _, rest = text.partition(" ")
    upper = token.upper()
    if upper in SMTP_COMMANDS:
        return upper, rest.strip()
    if upper in TWO_TOKEN_COMMANDS:
        prefix, name = TWO_TOKEN_COMMANDS[upper]
        if rest.upper().startswith(prefix):
            return name, rest[len(prefix) :].strip()
    return None
