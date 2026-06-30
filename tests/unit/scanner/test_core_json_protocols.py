"""Scanner regressions for stdlib JSON model precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_json_loads_literal_lookup_without_null_dereference(tmp_path: Path) -> None:
    target = tmp_path / "json_loads_literal_lookup.py"
    target.write_text(
        "def target() -> int:\n"
        "    import json\n"
        "\n"
        '    result = json.loads("{\\"x\\": 2}")["x"]\n'
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"NULL_DEREFERENCE", "KEY_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"}
        for issue in result.issues
    )
    assert "unsupported_subscript_abstraction" not in result.degraded_passes


def test_scan_file_preserves_values_across_literal_data_models(tmp_path: Path) -> None:
    target = tmp_path / "literal_data_models.py"
    target.write_text(
        "import ast\n"
        "import json\n"
        "import tomllib\n"
        "\n"
        "def target() -> int:\n"
        "    encoded = json.dumps({'json': 2}, sort_keys=True)\n"
        "    from_json = json.loads(encoded)['json']\n"
        "    from_literal = ast.literal_eval(\"{'literal': 3}\")['literal']\n"
        "    from_toml = tomllib.loads('toml = 4')['toml']\n"
        "    return from_json + from_literal + from_toml\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR", "NULL_DEREFERENCE"}
        for issue in result.issues
    )
    assert "unsupported_subscript_abstraction" not in result.degraded_passes
