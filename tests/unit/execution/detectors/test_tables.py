"""Tests for execution-owned detector dispatch tables."""

from __future__ import annotations

import dis

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.detectors.tables import build_detector_runtime_tables


class UniversalIssueDetector(Detector):
    """Detector that reports once for any opcode."""

    name = "unit-universal-runtime"
    description = "reports at every opcode"
    issue_kind = IssueKind.UNKNOWN
    relevant_opcodes: frozenset[str] = frozenset()

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        _ = state
        _ = instruction
        return Issue(kind=self.issue_kind, message="runtime issue", pc=0, line_number=99)


class ReturnOnlyDetector(Detector):
    """Detector used to verify opcode-specific runtime dispatch tables."""

    name = "unit-return-runtime"
    description = "reports on returns"
    issue_kind = IssueKind.UNKNOWN
    relevant_opcodes: frozenset[str] = frozenset({"RETURN_VALUE"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        _ = state
        _ = instruction
        return None


def test_build_detector_runtime_tables_separates_universal_and_opcode_specific() -> None:
    registry = DetectorRegistry()
    registry.register(UniversalIssueDetector)
    registry.register(ReturnOnlyDetector)

    tables = build_detector_runtime_tables(
        config=ExecutionConfig(),
        detector_registry=registry,
    )

    assert [detector.name for detector in tables.universal_detectors] == ["unit-universal-runtime"]
    assert [detector.name for detector in tables.detector_dispatch["RETURN_VALUE"]] == [
        "unit-return-runtime"
    ]
    assert [detector.name for detector in tables.active_detectors] == [
        "unit-universal-runtime",
        "unit-return-runtime",
    ]
