from __future__ import annotations

from pathlib import Path

import z3

from pysymex.analysis.detectors import Issue, IssueKind, Severity
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.detectors import DeferredDetectorIssue
from pysymex.execution.frontier import (
    FrontierRuntimeMode,
    FrontierSpillPolicy,
    FrontierSpillStatus,
    FrontierWorkStore,
    state_shadow_digest,
)


def _filesystem_spill_policy(tmp_path: Path) -> FrontierSpillPolicy:
    """Return a filesystem spill policy rooted in the test temp directory."""
    return FrontierSpillPolicy(
        filesystem_spill_enabled=True,
        spill_directory=tmp_path / "frontier-spill",
    )


def test_frontier_spill_policy_fails_closed_by_default() -> None:
    """Spill is observable but disabled until a safe serializer exists."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=4)
    store.add_state(0, state)

    decision = store.request_spill(0)
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.DISABLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert store.collect_stats().spill_denied_count == 1


def test_frontier_spill_policy_requires_explicit_root_when_enabled() -> None:
    """Filesystem spill requires a configured directory before it writes."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(0, VMState(pc=5))

    decision = store.request_spill(
        0,
        FrontierSpillPolicy(filesystem_spill_enabled=True),
    )

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.INVALID_SPILL_ROOT
    assert len(store) == 1
    assert store.collect_stats().spill_denied_count == 1


def test_frontier_spill_policy_spills_solver_constraints_with_primitive_roots(
    tmp_path: Path,
) -> None:
    """Solver-backed primitive checkpoints round-trip through deterministic SMT2."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    symbol = z3.Int("frontier_spill_rejects_solver_constraints")
    constraints = [symbol > 0, symbol < 10]
    state = VMState(
        pc=5,
        path_id=11,
        path_constraints=constraints,
        pending_constraint_count=2,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert decision.spill_path is not None
    assert decision.spill_path.exists()
    selected = store.pop_materialized(0)

    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert all(
        z3.eq(actual, expected)
        for actual, expected in zip(
            selected.path_constraints.to_list(),
            constraints,
            strict=True,
        )
    )
    assert not decision.spill_path.exists()


def test_frontier_spill_policy_rejects_symbolic_roots_when_enabled(tmp_path: Path) -> None:
    """Target-derived symbolic roots remain resident until object-safe spill exists."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    value, constraint = SymbolicValue.symbolic("frontier_spill_symbolic_root")
    store.add_state(
        0,
        VMState(
            stack=[value],
            pc=5,
            path_constraints=[constraint],
            pending_constraint_count=1,
        ),
    )

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert len(store) == 1
    assert store.collect_stats().checkpoint_count == 1
    assert store.collect_stats().spill_denied_count == 1


def test_frontier_spill_policy_reports_write_failure_without_mutation(tmp_path: Path) -> None:
    """A bad spill root is surfaced as a typed write failure and keeps work live."""
    spill_root = tmp_path / "not-a-directory"
    spill_root.write_text("occupied", encoding="utf-8")
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(pc=5, path_id=8)
    store.add_state(0, state)

    decision = store.request_spill(
        0,
        FrontierSpillPolicy(
            filesystem_spill_enabled=True,
            spill_directory=spill_root,
        ),
    )

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.WRITE_FAILED
    assert len(store) == 1
    assert store.collect_stats().checkpoint_count == 1
    assert store.collect_stats().spill_denied_count == 1
    assert spill_root.read_text(encoding="utf-8") == "occupied"


def test_frontier_spill_policy_rejects_direct_state_payloads(tmp_path: Path) -> None:
    """Shadow/direct entries are not serialized by the compact-checkpoint spill policy."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_SHADOW)
    store.add_state(0, VMState(pc=5))

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert len(store) == 1
    assert store.collect_stats().checkpoint_count == 0
    assert store.collect_stats().spill_denied_count == 1


def test_frontier_spill_policy_preserves_model_free_detector_sidecars(tmp_path: Path) -> None:
    """Model-free detector sidecars can spill without dropping pending evidence."""
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible zero divisor",
        pc=7,
        line_number=12,
        function_name="target",
        counterexample={"x": 0},
        confidence=0.5,
        severity=Severity.HIGH,
        detector_name="division",
    )
    deferred = DeferredDetectorIssue(issue, (999, 7, IssueKind.DIVISION_BY_ZERO))
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        pc=7,
        path_id=21,
        deferred_detector_issues=[deferred],
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.deferred_detector_issues == [deferred]
    assert selected.deferred_detector_issues[0].issue is not issue


def test_frontier_spill_policy_rejects_detector_sidecars_with_solver_evidence(
    tmp_path: Path,
) -> None:
    """Detector sidecars with issue-local solver evidence remain live."""
    symbol = z3.Int("frontier_spill_detector_sidecar_solver_evidence")
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible zero divisor",
        constraints=[symbol == 0],
        pc=7,
    )
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        pc=7,
        deferred_detector_issues=[
            DeferredDetectorIssue(issue, (999, 7, IssueKind.DIVISION_BY_ZERO)),
        ],
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert selected is state
    assert len(store) == 0
    assert store.collect_stats().spill_denied_count == 1


def test_frontier_spill_policy_spills_and_reconstructs_primitive_checkpoint(
    tmp_path: Path,
) -> None:
    """Primitive compact checkpoints can leave resident memory and reload exactly."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        stack=[1, "value", True, None],
        local_vars={"x": 1},
        global_vars={"g": "value"},
        memory={7: 3.5},
        pc=5,
        visited_pcs={1, 5},
        path_id=9,
        depth=2,
        open_resources=1,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert decision.spill_path is not None
    assert decision.spill_path.exists()
    stats_after_spill = store.collect_stats()
    assert stats_after_spill.checkpoint_count == 0
    assert stats_after_spill.spilled_entry_count == 1
    assert stats_after_spill.spill_denied_count == 0

    selected = store.pop_materialized(0)

    assert selected is not None
    assert selected is not state
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert not decision.spill_path.exists()
    assert store.collect_stats().spilled_entry_count == 0


def test_frontier_spill_policy_discards_spilled_file_without_materializing(
    tmp_path: Path,
) -> None:
    """Discarding certificate-pruned spilled work cleans up the spill file."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(0, VMState(pc=5, path_id=4))
    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    assert decision.spill_path is not None
    assert decision.spill_path.exists()

    store.discard(0)

    assert not decision.spill_path.exists()
    assert len(store) == 0
    assert store.collect_stats().spilled_entry_count == 0


def test_frontier_spill_policy_reports_stale_entries_without_mutation() -> None:
    """A stale spill request is typed and does not affect live entries."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    store.add_state(1, VMState(pc=6))

    decision = store.request_spill(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.NOT_LIVE
    assert tuple(store.live_state_ids) == (1,)
    assert store.collect_stats().spill_denied_count == 1
