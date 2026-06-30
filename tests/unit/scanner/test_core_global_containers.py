"""Scanner regressions for module-global mutable containers."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_allows_global_mutable_container_mutations(tmp_path: Path) -> None:
    target = tmp_path / "global_container_mutations.py"
    target.write_text(
        "GLOBAL_LIST: list[int] = []\n"
        "GLOBAL_DICT: dict[str, int] = {}\n"
        "GLOBAL_SET = {1}\n\n"
        "def list_target(x: int) -> int:\n"
        "    GLOBAL_LIST.append(x)\n"
        "    return len(GLOBAL_LIST)\n\n"
        "def dict_target(x: int) -> int:\n"
        "    GLOBAL_DICT['x'] = x\n"
        "    return len(GLOBAL_DICT)\n\n"
        "def set_target(x: int) -> int:\n"
        "    GLOBAL_SET.add(x)\n"
        "    return len(GLOBAL_SET)\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=20,
        timeout=5.0,
    )

    assert result.error is None
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") in {"list_target", "dict_target", "set_target"}
        for issue in result.issues
    )
