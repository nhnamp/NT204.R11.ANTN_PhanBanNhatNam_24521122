import tomllib
from dataclasses import dataclass, field
from pathlib import Path


class RuleConfigError(Exception):
    """The rule config cannot be read or has a wrong value."""


@dataclass
class LoadedRules:
    """`lines` holds `(path, line_number, text)` for each rule line of the enabled files."""

    lines: list[tuple[str, int, str]] = field(default_factory=list)
    disabled_sids: list[int] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_disabled: int = 0


def load_rules(config_path: str | Path) -> LoadedRules:
    config_path = Path(config_path)
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
    except OSError as error:
        raise RuleConfigError(f"cannot read rule config {config_path}: {error.strerror or error}") from error
    except tomllib.TOMLDecodeError as error:
        raise RuleConfigError(f"rule config {config_path} is not valid TOML: {error}") from error

    loaded = LoadedRules(disabled_sids=_disabled_sids(config, config_path))
    entries = config.get("rule_files", [])
    if not isinstance(entries, list):
        raise RuleConfigError(f"rule config {config_path}: rule_files must be an array of tables")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RuleConfigError(f"rule config {config_path}: each rule_files entry needs a string path")
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuleConfigError(f"rule config {config_path}: enabled of {entry['path']} must be true or false")
        if not enabled:
            loaded.files_disabled += 1
            continue
        _read_file(config_path.parent / entry["path"], loaded)
    return loaded


def _disabled_sids(config: dict, config_path: Path) -> list[int]:
    sids = config.get("disabled_sids", [])
    if not isinstance(sids, list) or not all(isinstance(sid, int) and not isinstance(sid, bool) for sid in sids):
        raise RuleConfigError(f"rule config {config_path}: disabled_sids must be a list of integers")
    return sids


def _read_file(path: Path, loaded: LoadedRules) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        loaded.warnings.append(f"cannot read rule file {path}: {error.strerror or error}")
        return
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if line and not line.startswith("#"):
            loaded.lines.append((str(path), number, line))
