from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_respects_safe_custom_getitem_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_getitem_safe.py"
    target.write_text(
        "class Store:\n"
        "    def __getitem__(self, key: int) -> int:\n"
        "        if key == 0:\n"
        "            return 1\n"
        "        return key\n\n"
        "def target(value: int) -> int:\n"
        "    store = Store()\n"
        "    return 10 // store[value]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 9
        for issue in result.issues
    )


def test_scan_file_preserves_custom_getitem_zero_result_bug(tmp_path: Path) -> None:
    target = tmp_path / "custom_getitem_bug.py"
    target.write_text(
        "class Store:\n"
        "    def __getitem__(self, key: int) -> int:\n"
        "        return key\n\n"
        "def target(value: int) -> int:\n"
        "    store = Store()\n"
        "    return 10 // store[value]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_passes_same_instance_to_custom_getitem(tmp_path: Path) -> None:
    target = tmp_path / "custom_getitem_same_instance.py"
    target.write_text(
        "class Store:\n"
        "    def __getitem__(self, key: object) -> int:\n"
        "        return 1\n\n"
        "def target() -> int:\n"
        "    store = Store()\n"
        "    return 10 // store[store]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_passes_same_instance_to_custom_setitem(tmp_path: Path) -> None:
    target = tmp_path / "custom_setitem_same_instance.py"
    target.write_text(
        "class Store:\n"
        "    def __setitem__(self, key: object, value: int) -> None:\n"
        "        return None\n\n"
        "def target() -> None:\n"
        "    store = Store()\n"
        "    store[store] = 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_executes_custom_setitem_before_read(tmp_path: Path) -> None:
    target = tmp_path / "custom_setitem_safe.py"
    target.write_text(
        "class Store:\n"
        "    def __init__(self) -> None:\n"
        "        self.value = 0\n\n"
        "    def __setitem__(self, key: int, value: int) -> None:\n"
        "        self.value = 1 if value == 0 else value\n\n"
        "    def __getitem__(self, key: int) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    store = Store()\n"
        "    store[0] = value\n"
        "    return 10 // store[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 14
        for issue in result.issues
    )


def test_scan_file_executes_custom_delitem_before_read(tmp_path: Path) -> None:
    target = tmp_path / "custom_delitem_safe.py"
    target.write_text(
        "class Store:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __delitem__(self, key: int) -> None:\n"
        "        self.value = 1\n\n"
        "    def __getitem__(self, key: int) -> int:\n"
        "        return self.value\n\n"
        "def target(value: int) -> int:\n"
        "    store = Store(value)\n"
        "    del store[0]\n"
        "    return 10 // store[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 14
        for issue in result.issues
    )


def test_scan_file_executes_custom_index_for_native_read(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_read_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    return 10 // [1, 0][Index()]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "INDEX_ERROR", "DIVISION_BY_ZERO"}
        for issue in result.issues
    )


def test_scan_file_executes_custom_index_for_native_store(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_store_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    values = [0]\n"
        "    values[Index()] = 1\n"
        "    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "INDEX_ERROR", "DIVISION_BY_ZERO"}
        for issue in result.issues
    )


def test_scan_file_executes_custom_index_for_native_delete(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_delete_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "def target() -> int:\n"
        "    values = [0, 1]\n"
        "    del values[Index()]\n"
        "    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "INDEX_ERROR", "DIVISION_BY_ZERO"}
        for issue in result.issues
    )
