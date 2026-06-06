"""Detector benchmark runner for recall/precision measurement.

This harness executes curated buggy/clean corpus functions and computes:
- true positives / false negatives
- false positives / true negatives
- recall and precision
for each runtime detector.
"""

from __future__ import annotations

from tests.repro.detector_benchmark_cases import RUNTIME_CASES
from tests.repro.detector_benchmark_executor import (
    build_executor_for_detector as _build_executor_for_detector,
    load_runtime_corpus_module as _load_runtime_corpus_module,
)
from tests.repro.detector_benchmark_fallback import (
    make_instruction as _make_instruction,
    run_synthetic_case as _run_synthetic_case,
    template_instruction as _template_instruction,
)
from tests.repro.detector_benchmark_runner import (
    format_report,
    run_case as _run_case,
    run_runtime_detector_benchmark,
    score_detector as _score_detector,
)
from tests.repro.detector_benchmark_types import (
    BenchmarkCase,
    BenchmarkReport,
    CaseOutcome,
    DetectorScore,
)

__all__ = [
    "BenchmarkCase",
    "BenchmarkReport",
    "CaseOutcome",
    "DetectorScore",
    "RUNTIME_CASES",
    "_build_executor_for_detector",
    "_load_runtime_corpus_module",
    "_make_instruction",
    "_run_case",
    "_run_synthetic_case",
    "_score_detector",
    "_template_instruction",
    "format_report",
    "run_runtime_detector_benchmark",
]
