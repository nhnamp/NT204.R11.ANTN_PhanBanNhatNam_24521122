import pytest

from ids.engine.loader import RuleConfigError, load_rules


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_reads_rule_lines_and_skips_comments_and_blank_lines(tmp_path):
    rules = write(tmp_path, "local.rules", "# comment\n\n   \n  alert tcp any any -> any 80 (sid:1;)\n\t# indented\nalert udp any any -> any 53 (sid:2;)\n")
    config = write(tmp_path, "rules.toml", 'disabled_sids = [2]\n[[rule_files]]\npath = "local.rules"\n')
    loaded = load_rules(config)
    assert loaded.lines == [
        (str(rules), 4, "alert tcp any any -> any 80 (sid:1;)"),
        (str(rules), 6, "alert udp any any -> any 53 (sid:2;)"),
    ]
    assert loaded.disabled_sids == [2]
    assert loaded.warnings == []


def test_disabled_file_is_not_read_and_is_counted(tmp_path):
    write(tmp_path, "off.rules", "alert tcp any any -> any 80 (sid:1;)\n")
    config = write(tmp_path, "rules.toml", '[[rule_files]]\npath = "off.rules"\nenabled = false\n')
    loaded = load_rules(config)
    assert loaded.lines == []
    assert loaded.files_disabled == 1


def test_missing_file_gives_a_warning_and_loading_goes_on(tmp_path):
    write(tmp_path, "b.rules", "alert tcp any any -> any 80 (sid:1;)\n")
    config = write(tmp_path, "rules.toml", '[[rule_files]]\npath = "a.rules"\n[[rule_files]]\npath = "b.rules"\n')
    loaded = load_rules(config)
    assert len(loaded.warnings) == 1 and "a.rules" in loaded.warnings[0]
    assert len(loaded.lines) == 1


@pytest.mark.parametrize("text", ["this is = = not toml", 'disabled_sids = "x"', "[[rule_files]]\nenabled = true\n"])
def test_bad_config_raises_rule_config_error(tmp_path, text):
    with pytest.raises(RuleConfigError):
        load_rules(write(tmp_path, "rules.toml", text))


def test_missing_config_raises_rule_config_error(tmp_path):
    with pytest.raises(RuleConfigError):
        load_rules(tmp_path / "none.toml")
