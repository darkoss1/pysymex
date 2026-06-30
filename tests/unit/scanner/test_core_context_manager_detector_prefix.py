"""Scanner regressions for detector feasibility after context-manager side effects."""

from __future__ import annotations

import textwrap
from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_unbound_after_context_manager_tuple_append(
    tmp_path: Path,
) -> None:
    """Detector feasibility should reuse the known path prefix after with-body side effects."""
    target = tmp_path / "context_manager_append_then_unbound.py"
    target.write_text(
        "class Node:\n"
        "    def __init__(self) -> None:\n"
        "        self.events = []\n"
        "\n"
        "class Gate:\n"
        "    def __init__(self, node: Node, name: str) -> None:\n"
        "        self.node = node\n"
        "        self.name = name\n"
        "\n"
        "    def __enter__(self) -> Node:\n"
        "        self.node.events.append(('enter', self.name))\n"
        "        return self.node\n"
        "\n"
        "    def __exit__(self, exc_type, exc, tb) -> bool:\n"
        "        return False\n"
        "\n"
        "def target(mode: int, left: int, right: int) -> int:\n"
        "    node = Node()\n"
        "    with Gate(node, 'outer') as inner:\n"
        "        match {'mode': mode, 'node': inner}:\n"
        "            case {'mode': 10}:\n"
        "                if left > right:\n"
        "                    late = left\n"
        "                return late\n"
        "            case _:\n"
        "                return len(inner.events)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=500,
        max_iterations=20000,
        timeout=30,
    )

    assert result.degraded_passes == []
    assert any(
        issue.get("kind") == "UNBOUND_VARIABLE"
        and issue.get("function_name") == "target"
        and issue.get("line") == 24
        for issue in result.issues
    )


def test_scan_file_reports_unbound_after_match_ladder_without_solver_unknown(
    tmp_path: Path,
) -> None:
    """Repeated mapping-pattern length checks should not make later bugs inconclusive."""
    target = tmp_path / "match_ladder_context_unbound.py"
    target.write_text(
        textwrap.dedent(
            """\
            class Node:
                __match_args__ = ("kind", "items")

                def __init__(self, kind: str, items: list[int]) -> None:
                    self.kind = kind
                    self.items = items
                    self.events = []

            class Gate:
                def __init__(self, node: Node, name: str) -> None:
                    self.node = node
                    self.name = name

                def __enter__(self) -> Node:
                    self.node.events.append(("enter", self.name))
                    return self.node

                def __exit__(self, exc_type, exc, tb) -> bool:
                    self.node.events.append(("exit", self.name, exc_type is not None))
                    return False

            def target(mode: int, left: int, right: int) -> int:
                node = Node("red", [left, right])
                total = 0
                with Gate(node, "outer") as inner:
                    for index, value in enumerate((left, right)):
                        match {"mode": mode, "index": index, "node": inner}:
                            case {"mode": 4}:
                                none_value = None
                                return none_value.missing
                            case {"mode": 5, "node": Node(_, items)} if items:
                                return "prefix" - value
                            case {"mode": 8}:
                                raise RuntimeError("manual runtime branch")
                            case {"mode": 9}:
                                return missing_global
                            case {"mode": 10}:
                                if left > right:
                                    late = left
                                return late
                            case {"mode": 11}:
                                return inner.missing_hard
                            case _:
                                total += value
                return total
            """
        ),
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=500,
        max_iterations=20000,
        timeout=30,
    )

    assert "solver_unknown_path_feasibility" not in result.degraded_passes
    assert "solver_unknown_detector_query" not in result.degraded_passes
    assert any(
        issue.get("kind") == "UNBOUND_VARIABLE"
        and issue.get("function_name") == "target"
        and issue.get("line") == 40
        for issue in result.issues
    )
