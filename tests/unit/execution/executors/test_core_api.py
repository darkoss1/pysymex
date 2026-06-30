"""Tests for core symbolic executor public API behavior."""

from __future__ import annotations

import dis
from typing import cast
from unittest.mock import patch

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.runtime.user.exception import UserExceptionDetector
from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import VMStateError
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.executors.core import SymbolicExecutor
from pysymex._internal.execution.executors.executor.bootstrap import resolve_execution_config
from pysymex._internal.execution.executors.executor.entrypoints.mixin import (
    ExecutorEntrypointMixin as ExecutorEntrypointMixinExport,
)
from pysymex._internal.execution.executors.executor.entrypoints.mixin import (
    ExecutorEntrypointMixin as ExecutorEntrypointMixinOwner,
)
from pysymex._internal.execution.executors.executor.loop.mixin import (
    ExecutorLoopMixin as ExecutorLoopMixinExport,
)
from pysymex._internal.execution.executors.executor.loop.mixin import (
    ExecutorLoopMixin as ExecutorLoopMixinOwner,
)
from pysymex._internal.execution.fallback.infrastructure import (
    FP_FILTERING_DEGRADED_PASS,
    STATE_MERGER_DEGRADED_PASS,
)
from pysymex._internal.execution.fallback.types import FallbackKind, RiskLevel, SoundnessTag
from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
from tests.unit.execution.executors.core_executor_helpers import simple


def test_executor_loop_public_export_points_to_direct_owner() -> None:
    assert ExecutorLoopMixinExport is ExecutorLoopMixinOwner


def test_executor_entrypoint_public_export_points_to_direct_owner() -> None:
    assert ExecutorEntrypointMixinExport is ExecutorEntrypointMixinOwner


def test_executor_bootstrap_resolves_config_overrides_without_mutating_input() -> None:
    config = ExecutionConfig(max_paths=2, max_iterations=20)

    resolved = resolve_execution_config(config, {"max_paths": 7})

    assert resolved.max_paths == 7
    assert config.max_paths == 2


class TestSymbolicExecutorApi:
    """Test suite for core executor API behavior."""

    def test_add_detector_registers_universal_detector_for_dispatch(self) -> None:
        """Late-added universal detectors should run during execution."""

        class CountingDetector(Detector):
            name = "unit-counting-universal"
            description = "counts every opcode dispatch"
            issue_kind = IssueKind.UNKNOWN
            relevant_opcodes: frozenset[str] = frozenset()

            def __init__(self) -> None:
                self.seen_opcodes: list[str] = []

            def check(
                self,
                state: VMState,
                instruction: dis.Instruction,
                _solver_check: IsSatFn,
            ) -> Issue | None:
                _ = state
                _ = _solver_check
                self.seen_opcodes.append(instruction.opname)
                return None

        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        detector = CountingDetector()
        executor.add_detector(detector)
        result = executor.execute_function(simple, {"x": "int"})

        assert result.paths_explored >= 1
        assert detector.seen_opcodes

    def test_add_detector_registers_opcode_specific_detector_for_dispatch(self) -> None:
        """Late-added opcode-specific detectors should run only for matching opcodes."""

        class ReturnDetector(Detector):
            name = "unit-counting-return"
            description = "counts RETURN_VALUE dispatches"
            issue_kind = IssueKind.UNKNOWN
            relevant_opcodes: frozenset[str] = frozenset({"RETURN_VALUE"})

            def __init__(self) -> None:
                self.seen_opcodes: list[str] = []

            def check(
                self,
                state: VMState,
                instruction: dis.Instruction,
                _solver_check: IsSatFn,
            ) -> Issue | None:
                _ = state
                _ = _solver_check
                self.seen_opcodes.append(instruction.opname)
                return None

        executor = SymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        detector = ReturnDetector()
        executor.add_detector(detector)
        result = executor.execute_function(simple, {"x": "int"})

        assert result.paths_explored >= 1
        assert detector.seen_opcodes
        assert set(detector.seen_opcodes) == {"RETURN_VALUE"}

    def test_user_exception_detector_registers_as_opcode_specific(self) -> None:
        """Default unhandled-exception detection should not be a universal dispatch."""
        registry = DetectorRegistry()
        registry.register(UserExceptionDetector)

        class InspectingExecutor(SymbolicExecutor):
            def detector_dispatch_snapshot(self) -> tuple[list[str], dict[str, list[str]]]:
                return (
                    [detector.name for detector in self._universal_detectors],
                    {
                        opcode: [detector.name for detector in detectors]
                        for opcode, detectors in self._detector_dispatch.items()
                    },
                )

        executor = InspectingExecutor(
            ExecutionConfig(max_paths=2, max_iterations=20),
            detector_registry=registry,
        )
        universal_names, dispatch = executor.detector_dispatch_snapshot()

        assert universal_names == []
        assert dispatch == {
            "RAISE_VARARGS": ["user_exception"],
        }

    def test_execute_function(self) -> None:
        """Test execute_function behavior."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=8, max_iterations=80, timeout_seconds=5.0)
        )
        result = executor.execute_function(simple, {"x": "int"})
        assert result.function_name == "simple"
        assert result.paths_explored >= 1

    def test_execute_code(self) -> None:
        """Test execute_code behavior."""
        executor = SymbolicExecutor(
            ExecutionConfig(max_paths=8, max_iterations=80, timeout_seconds=5.0)
        )
        code = compile("x = 1\ny = x + 2", "<test>", "exec")
        result = executor.execute_code(code, {"x": "int"}, {"x": 1})
        assert result.source_file == "<test>"
        assert result.paths_explored >= 1

    def test_execute_code_reports_worklist_shadow_telemetry(self) -> None:
        """Real execution results expose no-behavior-change POLAR/CEGIS telemetry."""
        executor = SymbolicExecutor(
            ExecutionConfig(
                max_paths=8,
                max_iterations=80,
                timeout_seconds=5.0,
                frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_SHADOW,
            )
        )
        code = compile("if x:\n    y = 1\nelse:\n    y = 2\n", "<test-shadow>", "exec")

        result = executor.execute_code(code, {"x": "int"}, {})

        worklist_stats = cast("dict[str, object]", result.solver_stats["worklist"])
        assert isinstance(worklist_stats, dict)
        assert worklist_stats["enabled"] is True
        assert worklist_stats["pending_states"] == 0
        assert worklist_stats["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_SHADOW.value
        shadow_frontier_raw = worklist_stats["shadow_frontier"]
        shadow_cegis_raw = worklist_stats["shadow_cegis"]
        assert isinstance(shadow_frontier_raw, dict)
        assert isinstance(shadow_cegis_raw, dict)
        shadow_frontier = cast("dict[str, object]", shadow_frontier_raw)
        shadow_cegis = cast("dict[str, object]", shadow_cegis_raw)
        assert shadow_frontier["enabled"] is True
        assert shadow_frontier["capsule_count"] == 0
        assert shadow_frontier["checkpoint_count"] == 0
        assert shadow_frontier["capsule_digest_mismatch_count"] == 0
        assert shadow_frontier["reconstruction_mismatch_count"] == 0
        assert shadow_frontier["spill_denied_count"] == 0
        assert shadow_cegis["enabled"] is True
        assert shadow_cegis["bid_count"] == 0

    def test_execute_code_reports_polar_cegis_runtime_frontier_mode(self) -> None:
        """Runtime mode is visible in result diagnostics and keeps shadow owners active."""
        executor = SymbolicExecutor(
            ExecutionConfig(
                max_paths=8,
                max_iterations=80,
                timeout_seconds=5.0,
                frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
            )
        )
        code = compile("if x:\n    y = 1\nelse:\n    y = 2\n", "<test-polar-runtime>", "exec")

        result = executor.execute_code(code, {"x": "int"}, {})

        worklist_stats = cast("dict[str, object]", result.solver_stats["worklist"])
        assert result.paths_explored >= 1
        assert worklist_stats["frontier_mode"] == FrontierRuntimeMode.POLAR_CEGIS_RUNTIME.value
        shadow_frontier = cast("dict[str, object]", worklist_stats["shadow_frontier"])
        shadow_cegis = cast("dict[str, object]", worklist_stats["shadow_cegis"])
        assert shadow_frontier["enabled"] is True
        assert shadow_frontier["capsule_count"] == 0
        assert shadow_frontier["checkpoint_count"] == 0
        assert shadow_frontier["spill_denied_count"] == 0
        assert shadow_cegis["enabled"] is True
        assert "runtime_execution_select_count" in shadow_cegis
        assert "runtime_execution_no_selection_count" in shadow_cegis

    def test_state_merger_prepass_failure_records_fallback_event(self) -> None:
        """State-merger setup failures should retain degraded label compatibility."""
        with patch(
            "pysymex._internal.execution.executors.core.StateMerger.detect_join_points",
            side_effect=ValueError("boom"),
        ):
            executor = SymbolicExecutor(
                ExecutionConfig(
                    max_paths=2,
                    max_iterations=20,
                    enable_state_merging=True,
                    enable_caching=False,
                )
            )
            result = executor.execute_function(simple, {"x": "int"})

        assert result.degraded_passes == [STATE_MERGER_DEGRADED_PASS]
        event = executor.session.fallback_events[-1]
        assert event.kind is FallbackKind.PRECISION_LOSS
        assert event.label == STATE_MERGER_DEGRADED_PASS
        assert event.owner == "execution.scheduling.state_merger"
        assert event.false_positive_risk is RiskLevel.LOW
        assert event.false_negative_risk is RiskLevel.MEDIUM
        assert event.soundness is SoundnessTag.PRECISION_LOSS

    def test_fp_filtering_failure_records_fallback_event(self) -> None:
        """Final issue filtering failures should expose raw-issue degradation."""
        with patch(
            "pysymex._internal.execution.detectors.finalization.filter_issues",
            side_effect=TypeError("boom"),
        ):
            executor = SymbolicExecutor(
                ExecutionConfig(max_paths=2, max_iterations=20, enable_caching=False)
            )
            result = executor.execute_function(simple, {"x": "int"})

        assert result.degraded_passes == [FP_FILTERING_DEGRADED_PASS]
        event = executor.session.fallback_events[-1]
        assert event.kind is FallbackKind.PRECISION_LOSS
        assert event.label == FP_FILTERING_DEGRADED_PASS
        assert event.owner == "execution.detectors.fp_filtering"
        assert event.false_positive_risk is RiskLevel.HIGH
        assert event.false_negative_risk is RiskLevel.LOW
        assert event.soundness is SoundnessTag.PRECISION_LOSS

    def test_execute_step_converts_vm_state_error_to_unknown_issue(self) -> None:
        """Internal VM stack failures should terminate the path as UNKNOWN, not crash scans."""
        executor = SymbolicExecutor(ExecutionConfig(max_paths=2, max_iterations=20))
        code = compile("x = 1", "<vm-state-error-test>", "exec")
        executor.session.instructions = list(dis.get_instructions(code))
        state = VMState(pc=0)

        def fail_dispatch(instr: dis.Instruction, state: VMState) -> OpcodeResult:
            _ = instr
            _ = state
            raise VMStateError("unit stack failure")

        executor.dispatcher.dispatch = fail_dispatch  # type: ignore[method-assign]

        executor.execute_step(state)

        assert executor.session.issues[-1].kind is IssueKind.UNKNOWN
        assert "unit stack failure" in executor.session.issues[-1].message
        assert executor.session.paths_pruned == 1
