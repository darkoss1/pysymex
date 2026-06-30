"""Scanner regressions for CPython 3.13 inlined comprehension bytecode."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_nested_listcomp_preserves_inner_list_items(tmp_path: Path) -> None:
    """Nested comprehension lists should not become arbitrary scalar values."""
    target = tmp_path / "nested_listcomp_items.py"
    target.write_text(
        "def target(left: int, right: int) -> int:\n"
        "    rows = [[item for item in row] for row in ((left, 1), (right, 2))]\n"
        "    total = 0\n"
        "    for row in rows:\n"
        "        for item in row:\n"
        "            total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=120,
        max_depth=2000,
        max_iterations=30000,
        timeout=10,
        trace_enabled=False,
    )

    assert result.error is None
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") in {"TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def test_scan_file_tuple_genexpr_over_exact_source_preserves_items(tmp_path: Path) -> None:
    """tuple(genexpr) over exact finite items should not fall back to call havoc."""
    target = tmp_path / "tuple_genexpr_items.py"
    target.write_text(
        "def target(left: int, right: int) -> int:\n"
        "    values = tuple(item for item in (left, right, 1))\n"
        "    total = 0\n"
        "    for item in values:\n"
        "        total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=120,
        max_depth=2000,
        max_iterations=30000,
        timeout=10,
        trace_enabled=False,
    )

    assert result.error is None
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") in {"TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def test_scan_file_tuple_nested_genexpr_flattens_exact_rows(tmp_path: Path) -> None:
    """One-level flattening genexprs should preserve integer-only row contents."""
    target = tmp_path / "tuple_nested_genexpr_items.py"
    target.write_text(
        "def target(left: int, right: int) -> int:\n"
        "    rows = [[item for item in row] for row in ((left, 1), (right, 2))]\n"
        "    flat = tuple(item for row in rows for item in row)\n"
        "    total = 0\n"
        "    for item in flat:\n"
        "        total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=160,
        max_depth=3000,
        max_iterations=60000,
        timeout=12,
        trace_enabled=False,
    )

    assert result.error is None
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") in {"TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def test_scan_file_tuple_genexpr_with_closure_attribute_preserves_items(
    tmp_path: Path,
) -> None:
    """A bounded genexpr using a captured object's int attr should remain exact."""
    target = tmp_path / "tuple_genexpr_closure_attr.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, seed: int) -> None:\n"
        "        self.seed = seed\n"
        "\n"
        "def target(left: int, right: int) -> int:\n"
        "    box = Box(3)\n"
        "    values = tuple(item + box.seed for item in (left, right, 1))\n"
        "    total = 0\n"
        "    for item in values:\n"
        "        total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=160,
        max_depth=3000,
        max_iterations=60000,
        timeout=12,
        trace_enabled=False,
    )

    assert result.error is None
    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") in {"TYPE_ERROR", "UNKNOWN"}
        for issue in result.issues
    )


def test_scan_file_inline_dictcomp_over_enumerate_restores_fast_locals(
    tmp_path: Path,
) -> None:
    """Exact finite ``enumerate`` comprehensions should not widen into cleanup restores."""
    target = tmp_path / "inline_dictcomp_enumerate_restore.py"
    target.write_text(
        "def target(mode: int, value: int) -> int:\n"
        "    dispatch = {\n"
        "        index: name\n"
        "        for index, name in enumerate(\n"
        "            ('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l')\n"
        "        )\n"
        "    }\n"
        "    label = dispatch.get(mode, 'fallback')\n"
        "    match (mode, label, value >= 0):\n"
        "        case (8, 'h', _):\n"
        "            return value\n"
        "        case (10 | 11, _, _):\n"
        "            return value + 1\n"
        "        case (_, _, _):\n"
        "            return value + 2\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=200,
        max_depth=300,
        max_iterations=10000,
        timeout=10,
        trace_enabled=False,
    )

    assert result.error is None
    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("function_name") == "target" and issue.get("kind") == "UNKNOWN"
        for issue in result.issues
    )
