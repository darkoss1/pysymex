"""Scanner regressions for conditional modeled ``__getitem__`` mapping unpacking."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_accepts_modeled_conditional_getitem_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_conditional_getitem.py"
    target.write_text(
        "class ConditionalMap:\n"
        "    def keys(self):\n"
        "        return ['a', 'b']\n"
        "    def __getitem__(self, key):\n"
        "        if key == 'a':\n"
        "            return 3\n"
        "        if key == 'b':\n"
        "            return 5\n"
        "        raise KeyError(key)\n\n"
        "class ConditionalNonStringMap:\n"
        "    def keys(self):\n"
        "        return [1]\n"
        "    def __getitem__(self, key):\n"
        "        if key == 1:\n"
        "            return 2\n"
        "        raise KeyError(key)\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_conditional_ok() -> int:\n"
        "    return consume(**ConditionalMap())['a']\n\n"
        "def dict_unpack_conditional_bug() -> int:\n"
        "    data = {**ConditionalMap()}\n"
        "    return 10 // (data['a'] - 3)\n\n"
        "def kwargs_conditional_non_string() -> dict:\n"
        "    return consume(**ConditionalNonStringMap())\n\n"
        "def dict_unpack_conditional_non_string_bug() -> int:\n"
        "    data = {**ConditionalNonStringMap()}\n"
        "    return 10 // (data[1] - 2)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "kwargs_conditional_ok"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_conditional_bug"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_conditional_non_string"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_conditional_non_string_bug"
        for issue in result.issues
    )
