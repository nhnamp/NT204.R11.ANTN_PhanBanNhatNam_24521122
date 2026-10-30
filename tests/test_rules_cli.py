import json
from pathlib import Path

import pytest

from ids.cli import parse_args, run

PCAP = Path(__file__).parent / "fixtures" / "http_get.pcap"
RULES = """\
# comment
alert tcp any any -> any 80 (msg:"GET request"; sid:1; content:"GET "; depth:4; classtype:web; priority:2;)
alert tcp any any -> any 80 (msg:"post"; sid:2; content:"POST";)
alert tcp any any -> any 80 (msg:"same sid"; sid:1;)
alert tcp any any -> any 80 (msg:"regex"; sid:3; pcre:"/a/";)
alert tcp any any -> any 80 (msg:"off"; sid:4; content:"GET";)
"""


def lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def setup(tmp_path: Path, config: str = 'disabled_sids = [4]\n\n[[rule_files]]\npath = "a.rules"\n') -> list[str]:
    (tmp_path / "a.rules").write_text(RULES, encoding="utf-8")
    (tmp_path / "rules.toml").write_text(config, encoding="utf-8")
    return [
        "--pcap", str(PCAP), "--output", str(tmp_path / "e.jsonl"), "--flows-output", str(tmp_path / "f.jsonl"),
        "--rules-config", str(tmp_path / "rules.toml"), "--matches-output", str(tmp_path / "m.jsonl"),
        "--rules-report", str(tmp_path / "r.jsonl"),
    ]


def test_a_run_writes_the_matches_the_report_and_the_summary(tmp_path, capsys):
    assert run(parse_args(setup(tmp_path))) == 0

    matches = lines(tmp_path / "m.jsonl")
    assert [(item["sid"], item["priority"], item["application_protocol"]) for item in matches] == [(1, 2, "HTTP")]
    assert matches[0]["matched"][0]["keyword"] == "content"
    report = lines(tmp_path / "r.jsonl")
    assert [(item["line"], item["status"]) for item in report] == [
        (2, "valid"), (3, "valid"), (4, "invalid"), (5, "unsupported"), (6, "disabled"),
    ]
    assert report[2]["text"].endswith("(msg:\"same sid\"; sid:1;)")
    assert report[2]["reason"] == "duplicate sid 1" and report[2]["rule"] is None
    err = capsys.readouterr().err
    assert "a.rules:4: invalid: duplicate sid 1" in err
    assert "a.rules:5: unsupported:" in err
    for text in ("rules valid: 2", "rules invalid: 1", "rules unsupported: 1", "rules disabled: 1", "rule matches: 1", "engine errors: 0"):
        assert text in err


def test_a_bad_config_stops_the_run_with_exit_code_1(tmp_path, capsys):
    args = setup(tmp_path, config="not = [valid")
    assert run(parse_args(args)) == 1
    assert "error: rule config" in capsys.readouterr().err
    args[args.index("--rules-config") + 1] = str(tmp_path / "missing.toml")
    assert run(parse_args(args)) == 1
    assert "error: cannot read rule config" in capsys.readouterr().err
    assert not (tmp_path / "m.jsonl").exists()


def test_without_a_rules_config_no_engine_file_is_created(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert run(parse_args(["--pcap", str(PCAP), "--output", "e.jsonl", "--flows-output", "f.jsonl"])) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == ["e.jsonl", "f.jsonl"]
    assert "rule matches" not in capsys.readouterr().err


def test_the_engine_outputs_join_the_same_file_checks_and_preview_warns(tmp_path, capsys):
    args = setup(tmp_path)
    with pytest.raises(SystemExit):
        parse_args([*args, "--matches-output", str(tmp_path / "r.jsonl")])
    assert "--matches-output and --rules-report name the same file" in capsys.readouterr().err
    assert run(parse_args([*args, "--payload", "preview"])) == 0
    assert "--payload preview" in capsys.readouterr().err


def test_an_output_on_a_rule_file_stops_the_run_and_keeps_the_rules(tmp_path, capsys):
    argv = setup(tmp_path)
    argv[argv.index("--matches-output") + 1] = str(tmp_path / "a.rules")

    assert run(parse_args(argv)) == 1
    assert "--matches-output names a rule file" in capsys.readouterr().err
    assert (tmp_path / "a.rules").read_text(encoding="utf-8") == RULES
