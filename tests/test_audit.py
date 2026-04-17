import json
import pytest
from supportutils_scrub.audit import load_mappings_file


def test_load_valid_mapping(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({'ip': {'1.2.3.4': '198.16.0.1'}}))
    data = load_mappings_file(str(p))
    assert data['ip']['1.2.3.4'] == '198.16.0.1'


def test_load_malformed_mapping_exits(tmp_path, capsys):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    with pytest.raises(SystemExit) as ex:
        load_mappings_file(str(p))
    assert ex.value.code == 1
    captured = capsys.readouterr()
    assert "Malformed mapping file" in captured.err


def test_load_missing_mapping_exits(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    with pytest.raises(SystemExit) as ex:
        load_mappings_file(str(missing))
    assert ex.value.code == 1
    captured = capsys.readouterr()
    assert "not found" in captured.err
