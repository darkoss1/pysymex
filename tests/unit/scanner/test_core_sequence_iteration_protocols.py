from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file


def _assert_no_issue_kinds(result: object, forbidden: set[str]) -> None:
    issues = getattr(result, "issues", [])
    assert not any(_issue_kind(issue) in forbidden for issue in issues)


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_scan_file_uses_getitem_sequence_iteration_fallback(tmp_path: Path) -> None:
    target = tmp_path / "sequence_getitem_iteration.py"
    target.write_text(
        "class Seq:\n"
        "    def __getitem__(self, index: int) -> int:\n"
        "        if index < 2:\n"
        "            return index + 1\n"
        "        raise IndexError\n\n"
        "def target() -> int:\n"
        "    total = 0\n"
        "    for item in Seq():\n"
        "        total += item\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(
        result,
        {"TYPE_ERROR", "INDEX_ERROR", "UNHANDLED_EXCEPTION", "ATTRIBUTE_ERROR"},
    )


def test_scan_file_still_reports_direct_unhandled_index_error(tmp_path: Path) -> None:
    target = tmp_path / "direct_index_error.py"
    target.write_text(
        "def target() -> None:\n    raise IndexError\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(_issue_kind(issue) == "INDEX_ERROR" for issue in result.issues)


def test_scan_file_consumes_custom_iterator_stopiteration(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterator_stopiteration.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Counter:\n"
        "        def __iter__(self) -> object:\n"
        "            return self\n"
        "        def __next__(self) -> int:\n"
        "            raise StopIteration\n\n"
        "    result = 0\n"
        "    for item in Counter():\n"
        "        result = item\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(
        result,
        {"NAME_ERROR", "UNBOUND_VARIABLE", "UNHANDLED_EXCEPTION", "TYPE_ERROR"},
    )


def test_scan_file_still_reports_direct_unhandled_stopiteration(tmp_path: Path) -> None:
    target = tmp_path / "direct_stopiteration.py"
    target.write_text(
        "def target() -> None:\n    raise StopIteration\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(_issue_kind(issue) == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_scan_file_iter_callable_sentinel_loop_is_exact(tmp_path: Path) -> None:
    target = tmp_path / "iter_callable_sentinel.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = [1, 2, 0]\n"
        "    def next_value():\n"
        "        return values.pop(0)\n\n"
        "    total = 0\n"
        "    for item in iter(next_value, 0):\n"
        "        total += item\n"
        "    result = total\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(
        result,
        {"TYPE_ERROR", "ATTRIBUTE_ERROR", "NAME_ERROR", "UNBOUND_VARIABLE", "UNKNOWN"},
    )
    assert not result.degraded_passes


def test_scan_file_unpacks_exact_custom_iterable(tmp_path: Path) -> None:
    target = tmp_path / "custom_iterable_unpack.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Pair:\n"
        "        def __iter__(self):\n"
        "            return iter([2, 3])\n\n"
        "    left, right = Pair()\n"
        "    result = left + right\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(
        result,
        {"TYPE_ERROR", "ATTRIBUTE_ERROR", "NAME_ERROR", "UNBOUND_VARIABLE"},
    )
