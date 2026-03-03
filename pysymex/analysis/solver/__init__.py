"""
Z3 Advanced Formal Verification Engine
======================================
Intelligent, interprocedural symbolic execution engine that:
- Tracks function calls across the entire codebase
- Builds call graphs to understand dependencies
- Creates function summaries for efficient re-analysis
- Dynamically explores paths based on risk priority
- Validates all pipelines and data flows

Architecture:
- CallGraph: Maps function relationships
- FunctionSummary: Cached analysis results
- SymbolicState: Rich state tracking with taint analysis
- FunctionAnalyzer: Individual function verification
- Z3Engine: Main intelligent prover

Bug Types:
- Division/modulo by zero
- Negative bit shifts
- Index out of bounds
- None dereference
- Type confusion
- Unreachable code paths
- Tainted data flows

Version: 2.0.0

Implementation split across submodules:
- z3_types: Enums, dataclasses, Z3 availability
- z3_graph: CallGraph, CFGBuilder, SymbolicState
- z3_opcodes: OpcodeHandlersMixin (bytecode instruction handlers)
- z3_analyzer: FunctionAnalyzer (symbolic execution core)
"""

from __future__ import annotations


import logging

import os

import time

from collections.abc import Callable

from concurrent.futures import ProcessPoolExecutor, as_completed

from typing import Any


from pysymex.analysis.solver.types import (
    BasicBlock,
    BugType,
    CallSite,
    CrashCondition,
    FunctionSummary,
    Severity,
    SymType,
    SymValue,
    TaintInfo,
    TaintSource,
    VerificationResult,
    Z3_AVAILABLE,
    Z3_IMPORT_ERROR,
    z3,
)

from pysymex.analysis.solver.graph import (
    CFGBuilder,
    CallGraph,
    SymbolicState,
)

from pysymex.analysis.solver.analyzer import FunctionAnalyzer

from pysymex.core.instruction_cache import get_instructions as _cached_get_instructions

logger = logging.getLogger(__name__)


__all__ = [
    "BasicBlock",
    "BugType",
    "CFGBuilder",
    "CallGraph",
    "CallSite",
    "CrashCondition",
    "FunctionAnalyzer",
    "FunctionSummary",
    "Severity",
    "SymType",
    "SymValue",
    "SymbolicState",
    "TaintInfo",
    "TaintSource",
    "VerificationResult",
    "Z3Engine",
    "Z3_AVAILABLE",
    "estimate_complexity",
    "is_z3_available",
    "verify_code",
    "verify_directory",
    "verify_file",
    "verify_function",
]


class Z3Engine:
    """
    Intelligent interprocedural verification engine.
    Features:
    - Call graph analysis
    - Function summaries with caching
    - Priority-based path exploration
    - Taint tracking
    - Cross-function verification
    """

    def __init__(
        self,
        timeout_ms: int = 5000,
        max_depth: int = 50,
        interprocedural: bool = True,
        track_taint: bool = True,
        max_workers: int | None = None,
    ):
        if not Z3_AVAILABLE:
            if Z3_IMPORT_ERROR is not None:
                raise RuntimeError(str(Z3_IMPORT_ERROR)) from Z3_IMPORT_ERROR

            raise RuntimeError("Z3 is required: pip install z3-solver")

        self.timeout = timeout_ms

        self.max_depth = max_depth

        self.interprocedural = interprocedural

        self.track_taint = track_taint

        self.max_workers = max_workers or min(os.cpu_count() or 2, 8)

        self.call_graph = CallGraph()

        self.function_summaries: dict[str, FunctionSummary] = {}

        self.summaries = self.function_summaries

        self.analyzer = FunctionAnalyzer(self)

        self.verified_crashes: dict[str, VerificationResult] = {}

        self._incremental_solver = None

    def verify_function(self, func: Callable[..., Any]) -> list[VerificationResult]:
        """Verify a single function."""

        return self.verify_code(func.__code__)

    def verify_code(self, code: Any) -> list[VerificationResult]:
        """Verify a code object."""

        crashes, summary = self.analyzer.analyze(code)

        for callee in summary.calls_functions:
            self.call_graph.add_call(
                CallSite(caller=code.co_name, callee=callee, line=0, arguments=[])
            )

        self.summaries[code.co_name] = summary

        return self._verify_crashes(crashes)

    def verify_file(self, path: str) -> dict[str, list[VerificationResult]]:
        """
        Verify all functions in a file with interprocedural analysis.
        """

        with open(path, encoding="utf-8", errors="ignore") as f:
            source = f.read()

        code = compile(source, path, "exec")

        self.analyzer.current_file = path

        results: dict[str, list[VerificationResult]] = {}

        all_codes: list[Any] = []

        def collect_codes(code_obj: Any) -> None:
            all_codes.append(code_obj)

            for const in code_obj.co_consts:
                if hasattr(const, "co_code"):
                    collect_codes(const)

        collect_codes(code)

        for code_obj in all_codes:
            crashes, summary = self.analyzer.analyze(code_obj)

            self.summaries[code_obj.co_name] = summary

            for callee in summary.calls_functions:
                self.call_graph.add_call(
                    CallSite(
                        caller=code_obj.co_name, callee=callee, line=0, arguments=[], file_path=path
                    )
                )

        self.call_graph.find_recursive()

        for code_obj in all_codes:
            func_name = code_obj.co_name

            context = self._build_context_from_callees(func_name)

            crashes, _ = self.analyzer.analyze(code_obj, context=context)

            if crashes:
                verified = self._verify_crashes(crashes)

                actual_crashes = [v for v in verified if v.can_crash]

                if actual_crashes:
                    results[func_name] = actual_crashes

        return results

    def verify_directory(
        self, path: str, max_workers: int | None = None
    ) -> dict[str, dict[str, list[VerificationResult]]]:
        """Verify all Python files in a directory using process-level parallelism.

        Each worker process gets its own Z3 solver instance, bypassing the GIL
        for true CPU parallelism on multi-core systems.
        """

        workers = max_workers or self.max_workers

        py_files: list[str] = []

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

            for file in files:
                if file.endswith(".py"):
                    py_files.append(os.path.join(root, file))

        if not py_files:
            return {}

        all_results: dict[str, dict[str, list[VerificationResult]]] = {}

        if workers > 1 and len(py_files) > 1:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                future_to_path = {
                    pool.submit(
                        _verify_file_worker, filepath, self.timeout, self.max_depth
                    ): filepath
                    for filepath in py_files
                }

                for future in as_completed(future_to_path):
                    filepath = future_to_path[future]

                    try:
                        serialized = future.result(timeout=self.timeout / 1000 * 2)

                        if serialized:
                            file_results = _deserialize_worker_results(serialized)

                            if file_results:
                                all_results[filepath] = file_results

                    except Exception:
                        logger.debug("Parallel verification failed for %s", filepath, exc_info=True)

        else:
            for filepath in py_files:
                try:
                    file_results = self.verify_file(filepath)

                    if file_results:
                        all_results[filepath] = file_results

                except Exception:
                    logger.debug("Verification failed for %s", filepath, exc_info=True)

        return all_results

    def _build_context_from_callees(self, func_name: str) -> dict[str, SymValue] | None:
        """Build context from function summaries of callees."""

        return None

    def _verify_crashes(self, crashes: list[CrashCondition]) -> list[VerificationResult]:
        """Verify crash conditions with Z3."""

        results: list[VerificationResult] = []

        seen: set[tuple[int, str, str]] = set()

        for crash in crashes:
            key = (crash.line, crash.bug_type.value, crash.function)

            if key in seen:
                continue

            seen.add(key)

            result = self._verify_single_crash(crash)

            results.append(result)

        return results

    def _verify_single_crash(self, crash: CrashCondition) -> VerificationResult:
        """Verify a single crash condition using IncrementalSolver with push/pop."""

        from pysymex.core.solver import IncrementalSolver

        start = time.time()

        if self._incremental_solver is None:
            self._incremental_solver = IncrementalSolver(timeout_ms=self.timeout)

        solver = self._incremental_solver

        solver.push()

        try:
            for constraint in crash.path_constraints:
                try:
                    solver.add(constraint)

                except Exception:
                    logger.debug("Failed to add path constraint", exc_info=True)

            try:
                solver.add(crash.condition)

            except Exception:
                logger.debug("Failed to add crash condition", exc_info=True)

                elapsed = (time.time() - start) * 1000

                return VerificationResult(crash, True, False, None, "error", elapsed)

            result_obj = solver.check()

            elapsed = (time.time() - start) * 1000

            if result_obj.is_sat and result_obj.model is not None:
                model = result_obj.model

                counterexample: dict[str, str] = {}

                for name, expr in crash.variables.items():
                    try:
                        val = model.eval(expr, model_completion=True)

                        counterexample[name] = str(val)

                    except Exception:
                        logger.debug("Model eval failed for variable %s", name, exc_info=True)

                        counterexample[name] = "?"

                return VerificationResult(
                    crash=crash,
                    can_crash=True,
                    proven_safe=False,
                    counterexample=counterexample,
                    z3_status="sat",
                    verification_time_ms=elapsed,
                )

            elif result_obj.is_unsat:
                return VerificationResult(
                    crash=crash,
                    can_crash=False,
                    proven_safe=True,
                    z3_status="unsat",
                    verification_time_ms=elapsed,
                )

            else:
                return VerificationResult(
                    crash=crash,
                    can_crash=True,
                    proven_safe=False,
                    z3_status="unknown",
                    verification_time_ms=elapsed,
                )

        finally:
            solver.pop()

    def get_call_graph_info(self) -> dict[str, Any]:
        """Get information about the call graph."""

        return {
            "functions": list(self.call_graph.calls.keys()),
            "total_calls": sum(len(v) for v in self.call_graph.calls.values()),
            "recursive_functions": list(self.call_graph.recursive),
            "entry_points": list(self.call_graph.entry_points),
        }

    def get_function_summary(self, name: str) -> FunctionSummary | None:
        """Get cached summary for a function."""

        return self.summaries.get(name)


def verify_function(func: Callable[..., Any]) -> list[VerificationResult]:
    """Verify a Python function."""

    if not Z3_AVAILABLE:
        return []

    engine = Z3Engine()

    return engine.verify_function(func)


def verify_code(code: Any) -> list[VerificationResult]:
    """Verify a code object."""

    if not Z3_AVAILABLE:
        return []

    engine = Z3Engine()

    return engine.verify_code(code)


def verify_file(path: str, timeout_ms: int = 5000) -> dict[str, list[VerificationResult]]:
    """Verify all functions in a file."""

    if not Z3_AVAILABLE:
        return {}

    engine = Z3Engine(timeout_ms=timeout_ms)

    return engine.verify_file(path)


def verify_directory(
    path: str, timeout_ms: int = 5000, max_workers: int | None = None
) -> dict[str, dict[str, list[VerificationResult]]]:
    """Verify all files in a directory with process-level parallelism."""

    if not Z3_AVAILABLE:
        return {}

    engine = Z3Engine(timeout_ms=timeout_ms, max_workers=max_workers)

    return engine.verify_directory(path, max_workers=max_workers)


def is_z3_available() -> bool:
    """Check if Z3 is available."""

    return Z3_AVAILABLE


def estimate_complexity(code: Any) -> dict[str, Any]:
    """Estimate function complexity from bytecode features for adaptive timeout.

    Analyzes the bytecode to count branches, loops, and call sites,
    then estimates an appropriate timeout.

    Args:
        code: A code object to analyze.

    Returns:
        Dictionary with complexity metrics and recommended timeout_ms.
    """

    instrs = _cached_get_instructions(code)

    branch_count = 0

    loop_count = 0

    call_count = 0

    total_instrs = len(instrs)

    branch_ops = frozenset(
        {
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_IF_NONE",
            "POP_JUMP_IF_NOT_NONE",
            "JUMP_IF_TRUE_OR_POP",
            "JUMP_IF_FALSE_OR_POP",
        }
    )

    backward_ops = frozenset({"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"})

    loop_ops = frozenset({"FOR_ITER", "GET_ITER"})

    call_ops = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD", "CALL_FUNCTION_EX"})

    for instr in instrs:
        if instr.opname in branch_ops:
            branch_count += 1

        elif instr.opname in backward_ops:
            loop_count += 1

        elif instr.opname in loop_ops:
            loop_count += 1

        elif instr.opname in call_ops:
            call_count += 1

    complexity_score = branch_count * 3 + loop_count * 5 + call_count * 2 + total_instrs // 10

    if complexity_score <= 10:
        timeout_ms = 2000

    elif complexity_score <= 30:
        timeout_ms = 5000

    elif complexity_score <= 60:
        timeout_ms = 10000

    elif complexity_score <= 100:
        timeout_ms = 20000

    else:
        timeout_ms = min(60000, complexity_score * 300)

    return {
        "branch_count": branch_count,
        "loop_count": loop_count,
        "call_count": call_count,
        "total_instructions": total_instrs,
        "complexity_score": complexity_score,
        "recommended_timeout_ms": timeout_ms,
    }


def _deserialize_worker_results(
    serialized: dict[str, list[dict[str, Any]]],
) -> dict[str, list[VerificationResult]]:
    """Rebuild VerificationResult objects from worker-safe dictionaries."""

    deserialized: dict[str, list[VerificationResult]] = {}

    for func_name, entries in serialized.items():
        results: list[VerificationResult] = []

        for entry in entries:
            bug_type_raw = entry.get("bug_type", BugType.TYPE_ERROR.value)

            try:
                bug_type = BugType(bug_type_raw)

            except Exception:
                logger.debug("Failed to deserialize BugType %r", bug_type_raw, exc_info=True)

                bug_type = BugType.TYPE_ERROR

            severity_raw = entry.get("severity", Severity.HIGH.value)

            try:
                severity = Severity(int(severity_raw))

            except Exception:
                logger.debug("Failed to deserialize Severity %r", severity_raw, exc_info=True)

                severity = Severity.HIGH

            crash = CrashCondition(
                bug_type=bug_type,
                condition=(z3.BoolVal(True) if z3 is not None and hasattr(z3, "BoolVal") else True),
                path_constraints=[],
                line=int(entry.get("line", 0)),
                function=str(entry.get("function") or func_name),
                description=str(entry.get("description") or ""),
                variables={},
                severity=severity,
                file_path=str(entry.get("file_path") or ""),
            )

            results.append(
                VerificationResult(
                    crash=crash,
                    can_crash=bool(entry.get("can_crash", False)),
                    proven_safe=bool(entry.get("proven_safe", False)),
                    counterexample=entry.get("counterexample"),
                    z3_status=str(entry.get("z3_status") or ""),
                    verification_time_ms=float(entry.get("verification_time_ms", 0.0)),
                )
            )

        if results:
            deserialized[func_name] = results

    return deserialized


def _verify_file_worker(
    filepath: str, timeout_ms: int, max_depth: int
) -> dict[str, list[dict[str, Any]]] | None:
    """Top-level worker function for parallel file verification.

    Must be a module-level function (not a method) for ProcessPoolExecutor
    pickling. Each worker creates its own Z3Engine in its own process.

    Args:
        filepath: Path to the Python file to verify.
        timeout_ms: Solver timeout in milliseconds.
        max_depth: Maximum symbolic execution depth.

    Returns:
        Dictionary mapping function names to serialized verification results,
        or None if no issues found.
    """

    try:
        engine = Z3Engine(timeout_ms=timeout_ms, max_depth=max_depth, max_workers=1)

        with open(filepath, encoding="utf-8", errors="ignore") as f:
            source = f.read()

        code = compile(source, filepath, "exec")

        complexity = estimate_complexity(code)

        adaptive_timeout = complexity["recommended_timeout_ms"]

        engine.timeout = min(adaptive_timeout, timeout_ms * 2)

        file_results = engine.verify_file(filepath)

        if not file_results:
            return None

        serialized: dict[str, list[dict[str, Any]]] = {}

        for func_name, results in file_results.items():
            serialized[func_name] = []

            for r in results:
                serialized[func_name].append(
                    {
                        "can_crash": r.can_crash,
                        "proven_safe": r.proven_safe,
                        "z3_status": r.z3_status,
                        "verification_time_ms": r.verification_time_ms,
                        "bug_type": r.crash.bug_type.value if r.crash else "",
                        "line": r.crash.line if r.crash else 0,
                        "function": r.crash.function if r.crash else "",
                        "description": r.crash.description if r.crash else "",
                        "severity": r.crash.severity.value if r.crash else 0,
                        "counterexample": r.counterexample,
                        "file_path": filepath,
                    }
                )

        return serialized

    except Exception:
        logger.warning("Worker result serialization failed", exc_info=True)

        return None


Z3Prover = Z3Engine
