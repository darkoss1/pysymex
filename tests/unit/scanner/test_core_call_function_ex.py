"""Scanner regressions for ``CALL_FUNCTION_EX`` unpacking semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_reports_call_function_ex_unpack_type_errors(tmp_path: Path) -> None:
    target = tmp_path / "call_function_ex_unpack_errors.py"
    target.write_text(
        "def consume(*args, **kwargs):\n"
        "    return 1\n\n"
        "def star_bad() -> int:\n"
        "    return consume(*1)\n\n"
        "def kwargs_bad() -> int:\n"
        "    return consume(**1)\n\n"
        "def keyword_bad() -> int:\n"
        "    return consume(**{1: 2})\n\n"
        "def star_dict_ok() -> int:\n"
        "    return consume(*{'a': 1})\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "star_bad"
        and "argument after * must be an iterable, not int" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_bad"
        and "argument after ** must be a mapping, not int" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "keyword_bad"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "star_dict_ok"
        for issue in result.issues
    )


def test_scan_file_preserves_dict_unpack_non_string_keys(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_non_string_keys.py"
    target.write_text(
        "def int_key_bug() -> int:\n"
        "    data = {**{1: 0}}\n"
        "    return 10 // data[1]\n\n"
        "def string_lookup_is_not_int_key() -> int:\n"
        "    data = {**{1: 1}}\n"
        "    return data['1']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "int_key_bug"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "string_lookup_is_not_int_key"
        for issue in result.issues
    )


def test_scan_file_accepts_modeled_keys_getitem_mapping_unpack(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_keys_getitem_mapping.py"
    target.write_text(
        "class KeysOnly:\n"
        "    def __init__(self, data):\n"
        "        self.data = data\n"
        "    def keys(self):\n"
        "        return self.data.keys()\n"
        "    def __getitem__(self, key):\n"
        "        return self.data[key]\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_keys_only_ok() -> int:\n"
        "    return consume(**KeysOnly({'a': 3}))['a']\n\n"
        "def dict_unpack_keys_only_bug() -> int:\n"
        "    data = {**KeysOnly({1: 0})}\n"
        "    return 10 // data[1]\n\n"
        "def kwargs_keys_only_non_string() -> int:\n"
        "    return consume(**KeysOnly({1: 2}))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "kwargs_keys_only_ok"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_keys_only_bug"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_keys_only_non_string"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_modeled_instance_without_mapping_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_plain_object.py"
    target.write_text(
        "class Plain:\n"
        "    pass\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_plain_bad() -> dict:\n"
        "    return consume(**Plain())\n\n"
        "def dict_unpack_plain_bad() -> dict:\n"
        "    return {**Plain()}\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_plain_bad"
        and "argument after ** must be a mapping, not Plain" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "dict_unpack_plain_bad"
        and "'Plain' object is not a mapping" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_modeled_keys_returning_non_iterable(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_bad_keys.py"
    target.write_text(
        "class BadKeys:\n"
        "    def keys(self):\n"
        "        return 1\n"
        "    def __getitem__(self, key):\n"
        "        return 2\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_bad_keys() -> dict:\n"
        "    return consume(**BadKeys())\n\n"
        "def dict_unpack_bad_keys() -> dict:\n"
        "    return {**BadKeys()}\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_bad_keys"
        and "BadKeys.keys() returned a non-iterable (type int)" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "dict_unpack_bad_keys"
        and "BadKeys.keys() returned a non-iterable (type int)" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_accepts_modeled_constant_mapping_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_constant_mapping.py"
    target.write_text(
        "class ConstMap:\n"
        "    def keys(self):\n"
        "        return ('a',)\n"
        "    def __getitem__(self, key):\n"
        "        return 3\n\n"
        "class ConstNonStringMap:\n"
        "    def keys(self):\n"
        "        return (1,)\n"
        "    def __getitem__(self, key):\n"
        "        return 2\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_const_ok() -> int:\n"
        "    return consume(**ConstMap())['a']\n\n"
        "def dict_unpack_const_bug() -> int:\n"
        "    data = {**ConstMap()}\n"
        "    return 10 // (data['a'] - 3)\n\n"
        "def kwargs_const_non_string() -> dict:\n"
        "    return consume(**ConstNonStringMap())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "kwargs_const_ok"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_const_bug"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_const_non_string"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_accepts_modeled_literal_list_keys_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_literal_list_keys.py"
    target.write_text(
        "class ListKeysMap:\n"
        "    def keys(self):\n"
        "        return ['a']\n"
        "    def __getitem__(self, key):\n"
        "        return 3\n\n"
        "class ListKeysNonStringMap:\n"
        "    def keys(self):\n"
        "        return [1]\n"
        "    def __getitem__(self, key):\n"
        "        return 2\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_list_keys_ok() -> int:\n"
        "    return consume(**ListKeysMap())['a']\n\n"
        "def dict_unpack_list_keys_bug() -> int:\n"
        "    data = {**ListKeysMap()}\n"
        "    return 10 // (data['a'] - 3)\n\n"
        "def kwargs_list_keys_non_string() -> dict:\n"
        "    return consume(**ListKeysNonStringMap())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "kwargs_list_keys_ok"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_list_keys_bug"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_list_keys_non_string"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_accepts_modeled_key_sensitive_getitem_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_key_sensitive_getitem.py"
    target.write_text(
        "class KeySensitiveMap:\n"
        "    def keys(self):\n"
        "        return ['a', 'b']\n"
        "    def __getitem__(self, key):\n"
        "        return {'a': 3, 'b': 5}[key]\n\n"
        "class KeySensitiveNonStringMap:\n"
        "    def keys(self):\n"
        "        return [1]\n"
        "    def __getitem__(self, key):\n"
        "        return {1: 2}[key]\n\n"
        "def consume(**kwargs):\n"
        "    return kwargs\n\n"
        "def kwargs_key_sensitive_ok() -> int:\n"
        "    return consume(**KeySensitiveMap())['a']\n\n"
        "def dict_unpack_key_sensitive_bug() -> int:\n"
        "    data = {**KeySensitiveMap()}\n"
        "    return 10 // (data['a'] - 3)\n\n"
        "def kwargs_key_sensitive_non_string() -> dict:\n"
        "    return consume(**KeySensitiveNonStringMap())\n\n"
        "def dict_unpack_key_sensitive_non_string_bug() -> int:\n"
        "    data = {**KeySensitiveNonStringMap()}\n"
        "    return 10 // (data[1] - 2)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"KEY_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "kwargs_key_sensitive_ok"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_key_sensitive_bug"
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "kwargs_key_sensitive_non_string"
        and "keywords must be strings" in str(issue.get("message"))
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "dict_unpack_key_sensitive_non_string_bug"
        for issue in result.issues
    )
