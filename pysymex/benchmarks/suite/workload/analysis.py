# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Analysis-focused built-in benchmark workloads."""

from __future__ import annotations

import tempfile
from pathlib import Path

from pysymex.benchmarks.suite.workload.helpers import (
    solver_outcome_counts_from_stats,
    solver_queries_from_stats,
)
from pysymex.logger import get_logger

logger = get_logger(__name__)

_RUNTIME_DETECTOR_SCAN_SOURCE = """
def division_case(x: int) -> int:
    return 10 // x


def guarded_division_case(y: int) -> int:
    if y == 0:
        return 0
    return 10 // y


def assertion_case(flag: bool) -> int:
    assert flag
    return 1


def index_case(i: int) -> int:
    values = [1, 2, 3]
    return values[i]


def key_case(k: str) -> int:
    values = {"safe": 1}
    return values[k]
""".strip()


def bench_race_detection() -> dict[str, int]:
    """Benchmark: race detection with concurrent operations."""
    try:
        from pysymex.analysis.domains.concurrency import ConcurrencyAnalyzer
    except ImportError:
        logger.warning("ConcurrencyAnalyzer unavailable for benchmark workload", exc_info=True)
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    analyzer = ConcurrencyAnalyzer(timeout_ms=5000)
    ops = 0

    for var_idx in range(5):
        addr = f"shared_var_{var_idx}"

        analyzer.record_write("thread_0", addr, f"val_{ops}")
        ops += 1

        analyzer.record_read("thread_1", addr)
        ops += 1

    analyzer.get_all_issues()
    return {"instructions": ops, "paths": 0, "solver_calls": 0}


def bench_contract_verification() -> dict[str, int]:
    """Benchmark: ContractVerifier proving preconditions, postconditions and loop invariants."""
    try:
        from pysymex.contracts.types import Contract, ContractKind
        from pysymex.contracts.verifier import ContractVerifier
    except ImportError:
        logger.warning("ContractVerifier unavailable for benchmark workload", exc_info=True)
        return {"instructions": 0, "paths": 0, "solver_calls": 0}

    import z3

    def _pre(x: z3.ArithRef) -> z3.BoolRef:
        return x > 0

    def _post(y: z3.ArithRef) -> z3.BoolRef:
        return y > 0

    def _inv(i: z3.ArithRef) -> z3.BoolRef:
        return i >= 0

    verifier = ContractVerifier(timeout_ms=5000)
    pre = Contract(kind=ContractKind.REQUIRES, predicate=_pre)
    post = Contract(kind=ContractKind.ENSURES, predicate=_post)
    inv = Contract(kind=ContractKind.LOOP_INVARIANT, predicate=_inv)

    x = z3.Int("x")
    y = z3.Int("y")
    i = z3.Int("i")
    i_after = z3.Int("i_after")

    total_evals = 0

    for _ in range(50):
        verifier.verify_precondition(pre, [x > 5], {"x": x})
        total_evals += 1

        verifier.verify_postcondition(post, [pre], [y == x * 2], {"x": x, "y": y})
        total_evals += 1

        verifier.verify_loop_invariant(
            inv, z3.BoolVal(True), [i_after == i + 1], [i == 0], {"i": i}, {"i": i_after}
        )
        total_evals += 1

    return {"instructions": total_evals, "paths": 50, "solver_calls": total_evals * 4}


def bench_runtime_detector_scan() -> dict[str, int]:
    """Benchmark scanner-driven runtime detector issue production.

    The workload uses the real scanner and executor path with a curated source file that
    includes true-positive and guarded false-positive controls.
    """
    from pysymex.scanner.file import scan_file

    with tempfile.TemporaryDirectory(prefix="pysymex_bench_detectors_") as temp_dir:
        target = Path(temp_dir) / "detector_cases.py"
        target.write_text(_RUNTIME_DETECTOR_SCAN_SOURCE, encoding="utf-8")
        result = scan_file(
            target,
            max_paths=96,
            timeout=8.0,
            deterministic_mode=True,
            no_cache=True,
        )

    if result.error:
        raise RuntimeError(f"detector scan benchmark failed: {result.error}")

    return {
        "instructions": result.code_objects,
        "paths": result.paths_explored,
        "solver_calls": solver_queries_from_stats(result.solver_stats),
        "issues": len(result.issues),
        **solver_outcome_counts_from_stats(result.solver_stats),
    }
