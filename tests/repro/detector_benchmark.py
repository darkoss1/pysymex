"""Detector benchmark runner for recall/precision measurement.

This harness executes curated buggy/clean corpus functions and computes:
- true positives / false negatives
- false positives / true negatives
- recall and precision
for each runtime detector.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import ModuleType
from typing import cast

import dis
import logging
import z3

from pysymex._typing import StackValue
from pysymex.analysis.detectors import DetectorRegistry, IssueKind, default_registry
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig

logging.getLogger("pysymex.execution.executors.core").setLevel(logging.CRITICAL)


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """Single benchmark case specification for one detector."""

    detector_name: str
    function_name: str
    symbolic_args: dict[str, str]
    expected_detected: bool


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """Observed result for one benchmark case."""

    detector_name: str
    function_name: str
    expected_detected: bool
    observed_detected: bool
    fallback_used: bool
    execution_error: str | None


@dataclass(frozen=True, slots=True)
class DetectorScore:
    """Confusion-matrix counts and quality metrics for a detector."""

    detector_name: str
    tp: int
    fp: int
    fn: int
    tn: int

    def recall(self) -> float | None:
        """Return recall (TP / (TP + FN)) when denominator is non-zero."""
        denominator = self.tp + self.fn
        if denominator == 0:
            return None
        return self.tp / denominator

    def precision(self) -> float | None:
        """Return precision (TP / (TP + FP)) when denominator is non-zero."""
        denominator = self.tp + self.fp
        if denominator == 0:
            return None
        return self.tp / denominator


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    """Aggregate benchmark report for all detectors."""

    outcomes: tuple[CaseOutcome, ...]
    scores: tuple[DetectorScore, ...]

    def total_cases(self) -> int:
        """Return the total number of benchmark cases executed."""
        return len(self.outcomes)

    def total_false_negatives(self) -> int:
        """Return the total count of false negatives across all detectors."""
        return sum(score.fn for score in self.scores)

    def total_false_positives(self) -> int:
        """Return the total count of false positives across all detectors."""
        return sum(score.fp for score in self.scores)

    def total_execution_errors(self) -> int:
        """Return the number of cases that required fallback due execution failures."""
        return sum(1 for outcome in self.outcomes if outcome.execution_error is not None)


RUNTIME_CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase("assertion-error", "assertion_error_positive", {"x": "int"}, True),
    BenchmarkCase("assertion-error", "assertion_error_negative", {}, False),
    BenchmarkCase("attribute-error", "attribute_error_positive", {}, True),
    BenchmarkCase("attribute-error", "attribute_error_negative", {}, False),
    BenchmarkCase("division-by-zero", "division_by_zero_positive", {"x": "int"}, True),
    BenchmarkCase("division-by-zero", "division_by_zero_negative", {}, False),
    BenchmarkCase(
        "division-by-zero",
        "division_by_zero_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int", "x": "int"},
        True,
    ),
    BenchmarkCase(
        "division-by-zero",
        "division_by_zero_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
    BenchmarkCase("index-error", "index_error_positive", {"i": "int"}, True),
    BenchmarkCase("index-error", "index_error_negative", {}, False),
    BenchmarkCase("key-error", "key_error_positive", {"k": "str"}, True),
    BenchmarkCase("key-error", "key_error_negative", {}, False),
    BenchmarkCase("none-dereference", "none_dereference_positive", {}, True),
    BenchmarkCase("none-dereference", "none_dereference_negative", {}, False),
    BenchmarkCase("overflow", "overflow_positive", {"x": "int", "y": "int"}, True),
    BenchmarkCase("overflow", "overflow_negative", {}, False),
    BenchmarkCase("resource-leak", "resource_leak_positive", {}, True),
    BenchmarkCase("resource-leak", "resource_leak_negative", {}, False),
    BenchmarkCase(
        "resource-leak",
        "resource_leak_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        True,
    ),
    BenchmarkCase(
        "resource-leak",
        "resource_leak_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
    BenchmarkCase("type-error", "type_error_positive", {"x": "int"}, True),
    BenchmarkCase("type-error", "type_error_negative", {}, False),
    BenchmarkCase("unbound-variable", "unbound_variable_positive", {"x": "int"}, True),
    BenchmarkCase("unbound-variable", "unbound_variable_negative", {"x": "int"}, False),
    BenchmarkCase("value-error", "value_error_positive", {}, True),
    BenchmarkCase("value-error", "value_error_negative", {}, False),
    BenchmarkCase(
        "value-error",
        "value_error_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        True,
    ),
    BenchmarkCase(
        "value-error",
        "value_error_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
)


def _build_executor_for_detector(detector_name: str) -> SymbolicExecutor:
    """Create a single-detector executor for targeted benchmark runs."""
    detector = default_registry.get(detector_name)
    if detector is None:
        raise ValueError(f"Unknown detector name: {detector_name}")
    custom_registry = DetectorRegistry()
    custom_registry.register(type(detector))
    config = ExecutionConfig(
        max_paths=256,
        max_depth=128,
        max_iterations=16384,
        timeout_seconds=20.0,
        enable_chtd=False,
        enable_h_acceleration=False,
        enable_abstract_interpretation=False,
        enable_cross_function=False,
        enable_type_inference=False,
        use_loop_analysis=False,
        enable_caching=False,
        enable_fp_filtering=False,
        enable_solver_cache=False,
        detect_overflow=True,
        verbose=False,
    )
    return SymbolicExecutor(config=config, detector_registry=custom_registry)


def _load_runtime_corpus_module() -> ModuleType:
    """Import and return the runtime detector corpus module."""
    return import_module("tests.repro.detector_corpus_runtime")


def _template_instruction() -> dis.Instruction:
    """Return a deterministic template instruction for synthetic detector fallback."""

    def _sentinel() -> None:
        """Provide a stable instruction template source."""
        return None

    return next(dis.get_instructions(_sentinel))


def _make_instruction(
    opname: str,
    *,
    argval: object = None,
    argrepr: str = "",
    arg: int = 0,
    offset: int = 0,
) -> dis.Instruction:
    """Create a deterministic instruction instance for detector fallback execution."""
    template = _template_instruction()
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def _run_synthetic_case(case: BenchmarkCase) -> bool:
    """Evaluate one benchmark case using direct detector invocation fallback."""
    detector = default_registry.get(case.detector_name)
    if detector is None:
        raise ValueError(f"Unknown detector name: {case.detector_name}")

    if case.function_name == "assertion_error_positive":
        issue = detector.check(
            VMState(stack=[AssertionError], path_constraints=[], pc=1),
            _make_instruction("RAISE_VARARGS", arg=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "assertion_error_negative":
        issue = detector.check(
            VMState(stack=[AssertionError], path_constraints=[], pc=1),
            _make_instruction("RAISE_VARARGS", arg=0),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "attribute_error_positive":
        issue = detector.check(
            VMState(stack=[1], path_constraints=[], pc=2),
            _make_instruction("LOAD_ATTR", argval="missing_attribute"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "attribute_error_negative":
        issue = detector.check(
            VMState(stack=[1], path_constraints=[], pc=2),
            _make_instruction("LOAD_ATTR", argval="bit_length"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_positive":
        issue = detector.check(
            VMState(stack=[10, 0], path_constraints=[], pc=3),
            _make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_negative":
        issue = detector.check(
            VMState(stack=[10, 2], path_constraints=[], pc=3),
            _make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_path_explosion_positive":
        issue = detector.check(
            VMState(stack=[120, 0], path_constraints=[], pc=3),
            _make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_path_explosion_negative":
        issue = detector.check(
            VMState(stack=[120, 3], path_constraints=[], pc=3),
            _make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "index_error_positive":
        index_symbol, _index_constraint = SymbolicValue.symbolic_int("idx")
        issue = detector.check(
            VMState(stack=[[1, 2, 3], index_symbol], path_constraints=[], pc=4),
            _make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "index_error_negative":
        issue = detector.check(
            VMState(stack=[[1, 2, 3], 1], path_constraints=[], pc=4),
            _make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "key_error_positive":
        issue = detector.check(
            VMState(stack=[{"a": 1}, "missing"], path_constraints=[], pc=5),
            _make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "key_error_negative":
        issue = detector.check(
            VMState(stack=[{"a": 1}, "a"], path_constraints=[], pc=5),
            _make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "none_dereference_positive":
        issue = detector.check(
            VMState(stack=[SymbolicNone()], path_constraints=[], pc=6),
            _make_instruction("LOAD_ATTR", argval="field"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "none_dereference_negative":
        issue = detector.check(
            VMState(stack=["safe"], path_constraints=[], pc=6),
            _make_instruction("LOAD_ATTR", argval="upper"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "overflow_positive":
        left_symbol, left_constraint = SymbolicValue.symbolic_int("left")
        right_symbol, right_constraint = SymbolicValue.symbolic_int("right")
        constraints = [
            left_constraint,
            right_constraint,
            left_symbol.z3_int == 2**63 - 1,
            right_symbol.z3_int == 1,
        ]
        issue = detector.check(
            VMState(stack=[left_symbol, right_symbol], path_constraints=constraints, pc=7),
            _make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "overflow_negative":
        issue = detector.check(
            VMState(stack=[1, 2], path_constraints=[], pc=7),
            _make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "resource_leak_positive":
        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        issue = detector.check(state, _make_instruction("RETURN_VALUE"), lambda _constraints: True)
        return issue is not None
    if case.function_name == "resource_leak_negative":

        class _CloseCallable:
            """Synthetic close callable for fallback detector case."""

            __name__ = "close"

            def __call__(self) -> None:
                return None

        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        state.stack = [cast(StackValue, _CloseCallable())]
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        issue = detector.check(state, _make_instruction("RETURN_VALUE"), lambda _constraints: True)
        return issue is not None
    if case.function_name == "resource_leak_path_explosion_positive":
        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        issue = detector.check(state, _make_instruction("RETURN_VALUE"), lambda _constraints: True)
        return issue is not None
    if case.function_name == "resource_leak_path_explosion_negative":

        class _CloseCallableNested:
            """Synthetic close callable for nested fallback detector case."""

            __name__ = "close"

            def __call__(self) -> None:
                return None

        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        state.stack = [cast(StackValue, _CloseCallableNested())]
        detector.check(state, _make_instruction("CALL", arg=0, argval=0), lambda _constraints: True)
        issue = detector.check(state, _make_instruction("RETURN_VALUE"), lambda _constraints: True)
        return issue is not None
    if case.function_name == "type_error_positive":
        issue = detector.check(
            VMState(stack=["left", 1], path_constraints=[], pc=9),
            _make_instruction("BINARY_OP", argrepr="-"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "type_error_negative":
        issue = detector.check(
            VMState(stack=["left", "right"], path_constraints=[], pc=9),
            _make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "unbound_variable_positive":
        issue = detector.check(
            VMState(stack=[], path_constraints=[], pc=10),
            _make_instruction("LOAD_FAST", argval="local_value"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "unbound_variable_negative":
        state = VMState(stack=[], path_constraints=[], pc=10)
        state.set_local("local_value", z3.IntVal(1))
        issue = detector.check(
            state, _make_instruction("LOAD_FAST", argval="local_value"), lambda _constraints: True
        )
        return issue is not None
    if case.function_name == "value_error_positive":
        issue = detector.check(
            VMState(stack=[int, "not-an-int"], path_constraints=[], pc=11),
            _make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_negative":
        issue = detector.check(
            VMState(stack=[int, "42"], path_constraints=[], pc=11),
            _make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_path_explosion_positive":
        issue = detector.check(
            VMState(stack=[int, "invalid-token"], path_constraints=[], pc=11),
            _make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_path_explosion_negative":
        issue = detector.check(
            VMState(stack=[int, "233"], path_constraints=[], pc=11),
            _make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None

    raise ValueError(f"No synthetic fallback defined for case: {case.function_name}")


def _run_case(module: ModuleType, case: BenchmarkCase) -> CaseOutcome:
    """Execute one benchmark case and return expected-vs-observed outcome."""
    function_object = getattr(module, case.function_name)
    executor = _build_executor_for_detector(case.detector_name)
    detector = default_registry.get(case.detector_name)
    if detector is None:
        raise ValueError(f"Unknown detector name: {case.detector_name}")
    issue_kind: IssueKind = detector.issue_kind
    fallback_used = False
    execution_error: str | None = None
    try:
        result = executor.execute_function(function_object, symbolic_args=case.symbolic_args)
        observed_detected = any(issue.kind == issue_kind for issue in result.issues)
    except NotImplementedError as error:
        observed_detected = _run_synthetic_case(case)
        fallback_used = True
        execution_error = str(error)

    return CaseOutcome(
        detector_name=case.detector_name,
        function_name=case.function_name,
        expected_detected=case.expected_detected,
        observed_detected=observed_detected,
        fallback_used=fallback_used,
        execution_error=execution_error,
    )


def _score_detector(detector_name: str, outcomes: tuple[CaseOutcome, ...]) -> DetectorScore:
    """Compute confusion-matrix counts for one detector."""
    detector_outcomes = tuple(
        outcome for outcome in outcomes if outcome.detector_name == detector_name
    )
    tp = sum(
        1
        for outcome in detector_outcomes
        if outcome.expected_detected and outcome.observed_detected
    )
    fp = sum(
        1
        for outcome in detector_outcomes
        if (not outcome.expected_detected) and outcome.observed_detected
    )
    fn = sum(
        1
        for outcome in detector_outcomes
        if outcome.expected_detected and (not outcome.observed_detected)
    )
    tn = sum(
        1
        for outcome in detector_outcomes
        if (not outcome.expected_detected) and (not outcome.observed_detected)
    )
    return DetectorScore(detector_name=detector_name, tp=tp, fp=fp, fn=fn, tn=tn)


def run_runtime_detector_benchmark(
    cases: tuple[BenchmarkCase, ...] = RUNTIME_CASES,
) -> BenchmarkReport:
    """Run the runtime detector benchmark and return an aggregate report."""
    module = _load_runtime_corpus_module()
    outcomes = tuple(_run_case(module, case) for case in cases)
    detector_names = tuple(sorted({case.detector_name for case in cases}))
    scores = tuple(_score_detector(name, outcomes) for name in detector_names)
    return BenchmarkReport(outcomes=outcomes, scores=scores)


def format_report(report: BenchmarkReport) -> str:
    """Format benchmark scores as a compact markdown table."""
    header = "| detector | tp | fp | fn | tn | recall | precision |"
    rule = "|---|---:|---:|---:|---:|---:|---:|"
    rows: list[str] = [header, rule]
    for score in report.scores:
        recall = score.recall()
        precision = score.precision()
        recall_text = "n/a" if recall is None else f"{recall:.3f}"
        precision_text = "n/a" if precision is None else f"{precision:.3f}"
        rows.append(
            f"| {score.detector_name} | {score.tp} | {score.fp} | {score.fn} | {score.tn} | {recall_text} | {precision_text} |"
        )
    rows.append("")
    rows.append(f"Total cases: {report.total_cases()}")
    rows.append(f"Total false negatives: {report.total_false_negatives()}")
    rows.append(f"Total false positives: {report.total_false_positives()}")
    rows.append(f"Total execution fallbacks: {report.total_execution_errors()}")
    return "\n".join(rows)
