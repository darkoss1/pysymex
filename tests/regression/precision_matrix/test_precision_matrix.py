"""End-to-end precision and recall regression matrix for adversarial scan cases."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.scanner.file import scan_file

MATRIX_ROOT = Path(__file__).parent
CASES_ROOT = MATRIX_ROOT / "cases"
MANIFEST_PATH = MATRIX_ROOT / "manifest.json"

MIN_TRUE_POSITIVES = 24
MAX_FALSE_NEGATIVES = 0
MAX_FALSE_POSITIVES = 0
MIN_TRUE_NEGATIVES = 24


@dataclass(frozen=True)
class PrecisionCase:
    """One manifest-owned oracle entry, never passed into scanner execution."""

    name: str
    label: bool
    category: str
    expected_issue_kinds: frozenset[str]


@dataclass(frozen=True)
class CaseObservation:
    """Observed scanner outcome for one precision case."""

    case: PrecisionCase
    issue_kinds: frozenset[str]
    degraded_passes: tuple[str, ...]
    elapsed_seconds: float

    @property
    def found_expected_issue(self) -> bool:
        return bool(self.issue_kinds & self.case.expected_issue_kinds)

    @property
    def outcome(self) -> str:
        if self.case.label:
            return "TP" if self.found_expected_issue else "FN"
        return "FP" if self.issue_kinds else "TN"


@dataclass(frozen=True)
class MatrixMetrics:
    """Aggregate binary-classification metrics for a complete matrix run."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def accuracy(self) -> float:
        total = (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )
        return (self.true_positives + self.true_negatives) / total if total else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0


def _required_str(item: Mapping[object, object], field: str) -> str:
    value = item.get(field)
    if not isinstance(value, str):
        raise AssertionError(f"manifest field {field!r} must be a string")
    return value


def _expected_issue_kinds(item: Mapping[object, object]) -> frozenset[str]:
    raw_kinds = item.get("expected_issue_kinds")
    if not RuntimeObjectGuards.list(raw_kinds) or not all(
        isinstance(kind, str) for kind in raw_kinds
    ):
        raise AssertionError("manifest expected_issue_kinds must be a list of strings")
    return frozenset(kind for kind in raw_kinds if isinstance(kind, str))


def _load_manifest() -> tuple[PrecisionCase, ...]:
    raw_manifest: object = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not RuntimeObjectGuards.list(raw_manifest):
        raise AssertionError("precision manifest must contain a JSON list")

    cases: list[PrecisionCase] = []
    for raw_item in raw_manifest:
        if not RuntimeObjectGuards.dict(raw_item):
            raise AssertionError("precision manifest entries must be JSON objects")
        label = raw_item.get("label")
        if not isinstance(label, bool):
            raise AssertionError("manifest label must be a boolean")
        cases.append(
            PrecisionCase(
                name=_required_str(raw_item, "name"),
                label=label,
                category=_required_str(raw_item, "category"),
                expected_issue_kinds=_expected_issue_kinds(raw_item),
            )
        )
    return tuple(cases)


def _observe_case(case: PrecisionCase) -> CaseObservation:
    target = CASES_ROOT / f"{case.name}.py"
    assert target.is_file(), f"missing precision case: {target}"

    result = scan_file(
        target,
        max_paths=1000,
        timeout=2.0,
        max_depth=400,
        use_sandbox=False,
        no_cache=True,
    )
    assert result.error is None, f"{case.name} scan failed: {result.error}"

    issue_kinds = frozenset(str(issue.get("kind", "UNKNOWN")) for issue in result.issues)
    return CaseObservation(
        case=case,
        issue_kinds=issue_kinds,
        degraded_passes=tuple(result.degraded_passes),
        elapsed_seconds=result.elapsed_time,
    )


def _metrics(observations: tuple[CaseObservation, ...]) -> MatrixMetrics:
    counts = {outcome: 0 for outcome in ("TP", "FP", "TN", "FN")}
    for observation in observations:
        counts[observation.outcome] += 1
    return MatrixMetrics(
        true_positives=counts["TP"],
        false_positives=counts["FP"],
        true_negatives=counts["TN"],
        false_negatives=counts["FN"],
    )


def _print_matrix(observations: tuple[CaseObservation, ...], metrics: MatrixMetrics) -> None:
    print("\nprecision matrix")
    for observation in observations:
        kinds = ",".join(sorted(observation.issue_kinds)) or "-"
        degraded = ",".join(observation.degraded_passes) or "-"
        print(
            f"{observation.outcome} {observation.case.name:<34} "
            f"issues={kinds:<32} degraded={degraded}"
        )
    print(
        "summary "
        f"TP={metrics.true_positives} FP={metrics.false_positives} "
        f"TN={metrics.true_negatives} FN={metrics.false_negatives} "
        f"precision={metrics.precision:.3f} recall={metrics.recall:.3f} "
        f"accuracy={metrics.accuracy:.3f} f1={metrics.f1:.3f}"
    )


def test_precision_matrix_preserves_baseline() -> None:
    cases = _load_manifest()
    assert len(cases) == 48
    assert sum(case.label for case in cases) == 24

    started = time.perf_counter()
    observations = tuple(_observe_case(case) for case in cases)
    metrics = _metrics(observations)
    _print_matrix(observations, metrics)
    print(f"matrix_wall_time={time.perf_counter() - started:.3f}s")

    assert metrics.true_positives >= MIN_TRUE_POSITIVES
    assert metrics.false_negatives <= MAX_FALSE_NEGATIVES
    assert metrics.false_positives <= MAX_FALSE_POSITIVES
    assert metrics.true_negatives >= MIN_TRUE_NEGATIVES
