"""Scanner regressions for stdlib contextlib protocol precision."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex
from pysymex.scanner.file import scan_file


_FORBIDDEN_KINDS = {
    "TYPE_ERROR",
    "ATTRIBUTE_ERROR",
    "NAME_ERROR",
    "UNBOUND_VARIABLE",
    "UNHANDLED_EXCEPTION",
    "NULL_DEREFERENCE",
}


def test_analyze_code_exitstack_enter_context_without_null_dereference() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "from contextlib import ExitStack\n"
            "\n"
            "class Manager:\n"
            "    def __init__(self, value):\n"
            "        self.value = value\n"
            "\n"
            "    def __enter__(self):\n"
            "        return self.value\n"
            "\n"
            "    def __exit__(self, exc_type, exc, tb):\n"
            "        return False\n"
            "\n"
            "with ExitStack() as stack:\n"
            "    value = stack.enter_context(Manager(2))\n"
            "    result = value + 3\n",
            max_paths=45,
            max_depth=130,
            max_iterations=3000,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) in _FORBIDDEN_KINDS for issue in result.issues
    )
    assert "unmodeled_call_abstraction" not in result.degraded_passes


def test_scan_file_exitstack_enter_context_without_null_dereference(tmp_path: Path) -> None:
    target = tmp_path / "exitstack_enter_context.py"
    target.write_text(
        "def target() -> int:\n"
        "    from contextlib import ExitStack\n"
        "\n"
        "    class Manager:\n"
        "        def __init__(self, value):\n"
        "            self.value = value\n"
        "\n"
        "        def __enter__(self):\n"
        "            return self.value\n"
        "\n"
        "        def __exit__(self, exc_type, exc, tb):\n"
        "            return False\n"
        "\n"
        "    with ExitStack() as stack:\n"
        "        value = stack.enter_context(Manager(2))\n"
        "        result = value + 3\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") in _FORBIDDEN_KINDS for issue in result.issues)
    assert "unmodeled_call_abstraction" not in result.degraded_passes


def test_analyze_code_contextmanager_generator_without_false_type_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "from contextlib import contextmanager\n"
            "\n"
            "@contextmanager\n"
            "def manager():\n"
            "    yield 4\n"
            "\n"
            "with manager() as value:\n"
            "    result = value + 1\n",
            max_paths=45,
            max_depth=130,
            max_iterations=3000,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) in _FORBIDDEN_KINDS for issue in result.issues
    )
    assert "unmodeled_call_abstraction" not in result.degraded_passes


def test_scan_file_contextmanager_generator_without_false_type_error(tmp_path: Path) -> None:
    target = tmp_path / "contextmanager_generator.py"
    target.write_text(
        "def target() -> int:\n"
        "    from contextlib import contextmanager\n"
        "\n"
        "    @contextmanager\n"
        "    def manager():\n"
        "        yield 4\n"
        "\n"
        "    with manager() as value:\n"
        "        result = value + 1\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") in _FORBIDDEN_KINDS for issue in result.issues)
    assert "unmodeled_call_abstraction" not in result.degraded_passes
