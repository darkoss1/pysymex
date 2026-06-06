"""Data models for runtime detector benchmark reporting."""

from __future__ import annotations

from dataclasses import dataclass


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
