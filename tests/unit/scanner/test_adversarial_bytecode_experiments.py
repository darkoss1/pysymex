from __future__ import annotations

import dis
from pathlib import Path
from typing import Any

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.scanner.file import scan_file


class CustomGetattributeCallTarget:
    def __init__(self, base: int) -> None:
        self.base = base

    def __getattribute__(self, name: str) -> Any:
        return object.__getattribute__(self, name)

    def method(self, value: int) -> int:
        return self.base + value


def stacked_custom_getattribute_call(left: int, prefix: int) -> int:
    target = CustomGetattributeCallTarget(left)
    return prefix + target.method(3)


def test_custom_getattribute_method_load_preserves_call_stack_layout() -> None:
    assert stacked_custom_getattribute_call(4, 5) == 12
    assert any(
        (instr.opname == "LOAD_ATTR" and instr.arg is not None and instr.arg & 1)
        or instr.opname == "LOAD_METHOD"
        for instr in dis.Bytecode(stacked_custom_getattribute_call)
    )

    result = SymbolicExecutor(
        ExecutionConfig(max_paths=12, max_iterations=800, timeout_seconds=6)
    ).execute_function(stacked_custom_getattribute_call, {"left": "int", "prefix": "int"})

    assert result.issues == []
    assert result.degraded_passes == []


def test_scan_file_retained_frozenset_membership_keeps_except_star_branch_precise(
    tmp_path: Path,
) -> None:
    target = tmp_path / "retained_frozenset_membership_except_star.py"
    target.write_text(
        "def score(value: int) -> int:\n"
        "    total = value + 6\n"
        "    try:\n"
        "        if value in {3, 4, 6}:\n"
        "            raise ExceptionGroup('grouped', [ValueError('member')])\n"
        "        total = -3\n"
        "    except* ValueError as group:\n"
        "        total += len(group.exceptions)\n"
        "    return total\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    payload = {'value': value}\n"
        "    match payload:\n"
        "        case {'value': guarded} if guarded == value:\n"
        "            return 100 // (score(value) + 1)\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=700,
        max_iterations=12000,
        timeout=10.0,
    )

    assert result.error is None
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
