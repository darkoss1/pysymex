"""Scanner regressions for bounded loop exploration soundness."""

from __future__ import annotations

import dis
from pathlib import Path
from types import CodeType

from pysymex._internal.scanner.file import scan_file


def _function_code(source: str) -> CodeType:
    module_code = compile(source, "<loop-bound-soundness>", "exec")
    return next(value for value in module_code.co_consts if isinstance(value, CodeType))


def test_scan_file_reports_unconditional_loop_as_structural_infinite_loop(
    tmp_path: Path,
) -> None:
    source = """
def target(x: int) -> int:
    total = 0
    while True:
        total += 1
    return total
"""
    function_code = _function_code(source)
    assert any(
        instruction.opname == "JUMP_BACKWARD" for instruction in dis.get_instructions(function_code)
    )

    target = tmp_path / "unconditional_loop.py"
    target.write_text(source, encoding="utf-8")

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=40,
        timeout=4,
        max_iterations=3000,
        auto_tune=False,
    )

    assert result.error is None
    assert not result.degraded_passes
    assert any(issue.get("kind") == "INFINITE_LOOP" for issue in result.issues)


def test_scan_file_finite_loop_control_stays_clean(tmp_path: Path) -> None:
    target = tmp_path / "finite_loop.py"
    target.write_text(
        """
def target() -> int:
    total = 0
    for value in [1, 2, 3]:
        total += value
    return total
""",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=40,
        timeout=4,
        max_iterations=3000,
    )

    assert result.error is None
    assert not result.degraded_passes
    assert not result.issues
