from __future__ import annotations

from pysymex._internal.execution.constants import BRANCH_OPCODES


def test_branch_opcodes_include_iteration_branch() -> None:
    assert "FOR_ITER" in BRANCH_OPCODES
