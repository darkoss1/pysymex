# pysymex: Python Symbolic Execution & Formal Verification
from __future__ import annotations

from pysymex.benchmarks.suite.workloads import create_builtin_benchmarks


def test_create_builtin_benchmarks_is_valid() -> None:
    suite = create_builtin_benchmarks()
    assert len(suite.benchmarks) > 0
    assert any(b.name == "simple_arithmetic" for b in suite.benchmarks)
