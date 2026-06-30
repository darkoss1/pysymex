"""Scanner regressions for bounded functools decorator behavior."""

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_lru_cache_decorator_preserves_nested_division_reachability(tmp_path: Path) -> None:
    target = tmp_path / "lru_cache_division.py"
    target.write_text(
        "import functools\n\n"
        "def target(value: int) -> int:\n"
        "    @functools.lru_cache(maxsize=128)\n"
        "    def cached(inner: int) -> int:\n"
        "        return 10 // inner\n"
        "    return cached(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_wraps_decorator_preserves_wrapper_division_reachability(tmp_path: Path) -> None:
    target = tmp_path / "wraps_division.py"
    target.write_text(
        "import functools\n\n"
        "def target(value: int) -> int:\n"
        "    def original(inner: int) -> int:\n"
        "        return 10 // inner\n"
        "    @functools.wraps(original)\n"
        "    def wrapper(inner: int) -> int:\n"
        "        return original(inner - value)\n"
        "    return wrapper(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_reduce_empty_without_initializer_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "reduce_empty.py"
    target.write_text(
        "import functools\n\n"
        "def target() -> object:\n"
        "    return functools.reduce(lambda left, right: left + right, [])\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "reduce() of empty iterable with no initial value" in str(issue.get("message"))
        for issue in result.issues
    )


def test_reduce_empty_with_initializer_does_not_report_type_error(tmp_path: Path) -> None:
    target = tmp_path / "reduce_initialized.py"
    target.write_text(
        "import functools\n\n"
        "def target() -> int:\n"
        "    return functools.reduce(lambda left, right: left + right, [], 0)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_cached_property_getter_preserves_division_reachability(tmp_path: Path) -> None:
    target = tmp_path / "cached_property_division.py"
    target.write_text(
        "import functools\n\n"
        "def target() -> int:\n"
        "    class Circle:\n"
        "        def __init__(self, radius: float):\n"
        "            self.radius = radius\n"
        "        @functools.cached_property\n"
        "        def units(self) -> int:\n"
        "            return int(self.radius)\n"
        "    circle = Circle(0.5)\n"
        "    return 100 // circle.units\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
