"""Scanner regressions for concrete user-defined context-manager suppression."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.analysis.scan.loading.globals import build_module_globals
from pysymex._internal.core.memory.cow.dicts import CowDict
from pysymex._internal.execution.detectors.suppression.managers import SuppressionManagerPolicy
from pysymex._internal.scanner.code import get_code_objects_with_context
from pysymex._internal.scanner.file import scan_file


def test_scan_file_allows_matching_user_context_manager_suppression(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_suppresses_division.py"
    target.write_text(
        "class SuppressZeroDivision:\n"
        "    def __enter__(self) -> 'SuppressZeroDivision':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc, tb\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with SuppressZeroDivision():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_allows_local_plain_context_manager_suppression(tmp_path: Path) -> None:
    target = tmp_path / "local_context_manager_suppresses_division.py"
    target.write_text(
        "def target() -> int:\n"
        "    class SuppressZero:\n"
        "        def __enter__(self):\n"
        "            return self\n"
        "\n"
        "        def __exit__(self, exc_type, exc, tb):\n"
        "            return exc_type is ZeroDivisionError\n"
        "\n"
        "    with SuppressZero():\n"
        "        1 / 0\n"
        "    result = 5\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "UNHANDLED_EXCEPTION"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_user_context_manager_that_propagates_division(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_propagates_division.py"
    target.write_text(
        "class PropagateZeroDivision:\n"
        "    def __enter__(self) -> 'PropagateZeroDivision':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc_type, exc, tb\n"
        "        return False\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with PropagateZeroDivision():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_reports_user_context_manager_matching_another_exception(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_matches_value_error.py"
    target.write_text(
        "class SuppressValueError:\n"
        "    def __enter__(self) -> 'SuppressValueError':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc, tb\n"
        "        return exc_type is ValueError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with SuppressValueError():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_reports_division_after_pre_with_modeled_attribute_read(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_manager_attribute_read_before_with.py"
    target.write_text(
        "class Node:\n"
        "    __match_args__ = ('kind', 'items')\n"
        "\n"
        "    def __init__(self, kind: str, items: list[int]) -> None:\n"
        "        self.kind = kind\n"
        "        self.items = items\n"
        "        self.events = []\n"
        "\n"
        "class Gate:\n"
        "    def __init__(self, node: Node, name: str, suppress_key: bool) -> None:\n"
        "        self.node = node\n"
        "        self.name = name\n"
        "        self.suppress_key = suppress_key\n"
        "\n"
        "    def __enter__(self) -> Node:\n"
        "        self.node.events.append(('enter', self.name))\n"
        "        self.node.items.append(len(self.node.events))\n"
        "        return self.node\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb) -> bool:\n"
        "        self.node.events.append(('exit', self.name, exc_type is not None))\n"
        "        return self.suppress_key and exc_type is KeyError\n"
        "\n"
        "def _mix(node: Node, pivot: int) -> list[tuple[int, int]]:\n"
        "    pairs = []\n"
        "    for index, item in enumerate((node.items[0], pivot)):\n"
        "        try:\n"
        "            pairs.append((index, item + 13))\n"
        "        finally:\n"
        "            node.events.append(('mix-finally', index, len(pairs)))\n"
        "    return pairs\n"
        "\n"
        "def target(mode: int, left: int, right: int, pivot: int) -> int:\n"
        "    node = Node('red', [left, right, pivot])\n"
        "    node.items\n"
        "    total = 0\n"
        "    with Gate(node, 'outer', mode == 3) as outer:\n"
        "        with Gate(outer, 'inner', mode == 30) as inner:\n"
        "            for index, value in _mix(inner, pivot):\n"
        "                match {'mode': mode, 'index': index, 'node': inner}:\n"
        "                    case {'mode': 0, 'index': 0, 'node': Node('red', [head, *_])}:\n"
        "                        return total + head // (left - right)\n"
        "                    case _:\n"
        "                        total += value + 13\n"
        "    return total\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=300,
        max_iterations=20000,
    )

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_does_not_trust_decorated_exit_method_body(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_decorated_exit.py"
    target.write_text(
        "def propagate(method: object) -> object:\n"
        "    def wrapper(*args: object) -> bool:\n"
        "        return False\n"
        "    return wrapper\n"
        "\n"
        "class DecoratedExit:\n"
        "    def __enter__(self) -> 'DecoratedExit':\n"
        "        return self\n"
        "    @propagate\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with DecoratedExit():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 16
        for issue in result.issues
    )


def test_inherited_manager_construction_is_not_certified_for_suppression() -> None:
    content = (
        "class Propagate:\n"
        "    def __enter__(self) -> 'Propagate':\n"
        "        return self\n"
        "    def __exit__(self, *args: object) -> bool:\n"
        "        return False\n"
        "\n"
        "class ReplaceOnConstruction:\n"
        "    def __new__(cls) -> Propagate:\n"
        "        return Propagate()\n"
        "\n"
        "class ClaimedSuppress(ReplaceOnConstruction):\n"
        "    def __enter__(self) -> 'ClaimedSuppress':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with ClaimedSuppress():\n"
        "        return 10 // denominator\n"
        "    return 0\n"
    )
    target = Path("context_manager_inherited_construction.py")
    code = compile(content, str(target), "exec")
    module_globals = build_module_globals(
        content=content,
        file_path=target,
        full_module_name="context_manager_inherited_construction",
        package_name="",
        all_code_with_context=get_code_objects_with_context(code),
    )

    assert not SuppressionManagerPolicy.known_suppresses(
        CowDict(module_globals), "ZeroDivisionError", "ClaimedSuppress", ()
    )
