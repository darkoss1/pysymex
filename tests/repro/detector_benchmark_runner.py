"""Runtime detector benchmark execution and scoring."""

from __future__ import annotations

from types import ModuleType

from pysymex.analysis.detectors import IssueKind, default_registry
from tests.repro.detector_benchmark_cases import RUNTIME_CASES
from tests.repro.detector_benchmark_executor import (
    build_executor_for_detector,
    load_runtime_corpus_module,
)
from tests.repro.detector_benchmark_fallback import run_synthetic_case
from tests.repro.detector_benchmark_types import (
    BenchmarkCase,
    BenchmarkReport,
    CaseOutcome,
    DetectorScore,
)


def run_case(module: ModuleType, case: BenchmarkCase) -> CaseOutcome:
    """Execute one benchmark case and return expected-vs-observed outcome."""
    function_object = getattr(module, case.function_name)
    executor = build_executor_for_detector(case.detector_name)
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
        observed_detected = run_synthetic_case(case)
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


def score_detector(detector_name: str, outcomes: tuple[CaseOutcome, ...]) -> DetectorScore:
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
    module = load_runtime_corpus_module()
    outcomes = tuple(run_case(module, case) for case in cases)
    detector_names = tuple(sorted({case.detector_name for case in cases}))
    scores = tuple(score_detector(name, outcomes) for name in detector_names)
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
