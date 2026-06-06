from __future__ import annotations

from pathlib import Path
from textwrap import dedent

from pytest import MonkeyPatch

from pysymex.execution.frontier import FrontierWorkStore
from pysymex.execution.scheduling.cegis import CegisRuntimeController
from pysymex.scanner.file import scan_file
from pysymex.scanner.types import ScanResult


def _scan_with_runtime_proof_enabled(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    source: str,
    *,
    max_paths: int = 80,
) -> tuple[ScanResult, int]:
    target = tmp_path / "runtime_proof_no_false_prune.py"
    target.write_text(dedent(source).lstrip(), encoding="utf-8")
    original_apply = CegisRuntimeController.apply_runtime_evidence
    proof_call_count = 0

    def counted_apply(
        self: CegisRuntimeController,
        frontier: FrontierWorkStore,
    ) -> None:
        nonlocal proof_call_count
        proof_call_count += 1
        original_apply(self, frontier)

    monkeypatch.setattr(CegisRuntimeController, "_RUNTIME_CEGIS_PROOF_FRONTIER_LIMIT", 100)
    monkeypatch.setattr(CegisRuntimeController, "apply_runtime_evidence", counted_apply)

    result = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        deterministic_mode=True,
        max_paths=max_paths,
        timeout=8,
    )
    return result, proof_call_count


def _issue_kinds(result: ScanResult) -> set[str]:
    return {str(issue["kind"]) for issue in result.issues}


def test_enabled_runtime_proof_preserves_feasible_division_issue(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target(x: int) -> int:
            if x > 0:
                return 10 // (x - x)
            return 1
        """,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert "DIVISION_BY_ZERO" in _issue_kinds(result)
    assert "solver_unknown_detector_query" not in result.degraded_passes


def test_enabled_runtime_proof_keeps_infeasible_sibling_non_reported(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target(x: int) -> int:
            if x > 0:
                if x <= 0:
                    return 10 // 0
            return 1
        """,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert "DIVISION_BY_ZERO" not in _issue_kinds(result)
    assert result.degraded_passes == []


def test_enabled_runtime_proof_preserves_null_detector_issue(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target(x: int) -> int:
            value = None
            if x > 0:
                return value.missing
            return 1
        """,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert "NULL_DEREFERENCE" in _issue_kinds(result)


def test_enabled_runtime_proof_preserves_unsupported_diagnostics(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target(left: object, right: object) -> object:
            if left:
                return left @ right
            return 0
        """,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert "unsupported_numeric_abstraction" in result.degraded_passes


def test_enabled_runtime_proof_preserves_path_limit_incomplete_status(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target(a: int, b: int, c: int) -> int:
            total = 0
            if a > 0:
                total += 1
            if b > 0:
                total += 1
            if c > 0:
                total += 1
            if total == 3:
                return 10 // (a - a)
            return total
        """,
        max_paths=1,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert "resource_limit_paths" in result.degraded_passes
    assert "DIVISION_BY_ZERO" in _issue_kinds(result)


def test_enabled_runtime_proof_preserves_havoc_precision_loss(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    result, proof_call_count = _scan_with_runtime_proof_enabled(
        tmp_path,
        monkeypatch,
        """
        def target() -> object:
            return object.__str__()
        """,
    )

    assert result.error is None
    assert proof_call_count > 0
    assert result.issues == []
    assert "unmodeled_call_abstraction" in result.degraded_passes
