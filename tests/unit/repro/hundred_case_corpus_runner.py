"""Execution helpers for the hundred-case symbolic-execution corpus."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig
from tests.unit.repro.hundred_case_corpus_cases import CorpusCase


def build_executor() -> SymbolicExecutor:
    return SymbolicExecutor(
        ExecutionConfig(
            max_paths=64,
            max_depth=96,
            max_iterations=4096,
            timeout_seconds=5.0,
            solver_timeout_ms=1000,
            enable_caching=False,
            enable_cross_function=False,
            enable_fp_filtering=False,
            enable_solver_cache=True,
            enable_state_merging=False,
            enable_type_inference=False,
            use_loop_analysis=False,
            verbose=False,
        )
    )


def compile_case(case: CorpusCase) -> Callable[..., object]:
    namespace: dict[str, object] = {}
    code = compile(case.source, f"<hundred-case:{case.name}>", "exec")
    exec(code, namespace)
    function = namespace[case.name]
    assert callable(function)
    return function
