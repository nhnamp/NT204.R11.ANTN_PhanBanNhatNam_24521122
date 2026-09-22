"""Entry point. Parse arguments, then hand control to ids.cli."""

import sys

from ids.cli import parse_args, run


def main(argv: list[str] | None = None) -> int:
    """Run one capture session and return its exit code."""
    return run(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
