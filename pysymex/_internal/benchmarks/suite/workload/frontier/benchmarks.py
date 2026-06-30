# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Frontier-focused built-in benchmark workloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.checkpoints import FrontierCheckpoint
    from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector
    from pysymex._internal.typing.protocols import StackValue

_FRONTIER_ADMISSION_STATE_COUNT = 250
_FRONTIER_ADMISSION_CONSTRAINT_COUNT = 8
_FRONTIER_ADMISSION_LOCAL_COUNT = 16
_FRONTIER_ADMISSION_PC_COUNT = 32
_FRONTIER_CEGIS_PREVIEW_STATE_COUNT = 64
_FRONTIER_CEGIS_PREVIEW_ITERATIONS = 32
_FRONTIER_CEGIS_SOLVER_STATE_COUNT = 8
_FRONTIER_CEGIS_SOLVER_ITERATIONS = 4


def bench_frontier_shadow_checkpoint_admission() -> dict[str, int]:
    """Benchmark: Shadow POLAR capsule creation during frontier admission."""
    return _bench_frontier_admission(frontier_mode="shadow", compact_runtime=False)


def bench_frontier_runtime_native_admission() -> dict[str, int]:
    """Benchmark: Default POLAR runtime admission with lazy capsules."""
    return _bench_frontier_admission(frontier_mode="runtime_native", compact_runtime=False)


def bench_frontier_runtime_compacted_admission() -> dict[str, int]:
    """Benchmark: POLAR runtime admission followed by exact checkpoint compaction."""
    return _bench_frontier_admission(frontier_mode="runtime_native", compact_runtime=True)


def bench_frontier_shadow_cegis_preview_execute() -> dict[str, int]:
    """Benchmark: CEGIS live-frontier preview with solver-free execute bids."""
    return _bench_frontier_shadow_cegis_preview(solver_unsat=False)


def bench_frontier_shadow_cegis_preview_unsat() -> dict[str, int]:
    """Benchmark: CEGIS live-frontier preview with explicit solver UNSAT evidence."""
    return _bench_frontier_shadow_cegis_preview(solver_unsat=True)


def _bench_frontier_admission(
    *,
    frontier_mode: str,
    compact_runtime: bool,
) -> dict[str, int]:
    """Benchmark state admission into the native frontier manager."""
    from pysymex._internal.execution.frontier.modes import FrontierRuntimeMode
    from pysymex._internal.execution.strategies.manager.path import AdaptivePathManager

    if frontier_mode == "shadow":
        mode = FrontierRuntimeMode.POLAR_CEGIS_SHADOW
    elif frontier_mode == "runtime_native":
        mode = FrontierRuntimeMode.POLAR_CEGIS_RUNTIME
    else:
        msg = f"unexpected frontier mode: {frontier_mode!r}"
        raise ValueError(msg)
    manager = AdaptivePathManager(
        _build_frontier_admission_graph(),
        frontier_runtime_mode=mode,
    )
    for state in _frontier_admission_states():
        manager.add_state(state)
    if compact_runtime:
        manager.compact_runtime_frontier()

    checkpoint_count = _frontier_checkpoint_count(manager.get_stats())
    expected_checkpoints = _FRONTIER_ADMISSION_STATE_COUNT if compact_runtime else 0
    if checkpoint_count != expected_checkpoints:
        msg_0 = (
            "frontier admission benchmark observed unexpected checkpoint count: "
            f"expected {expected_checkpoints}, got {checkpoint_count}"
        )
        raise RuntimeError(
            msg_0,
        )
    return {
        "instructions": _FRONTIER_ADMISSION_STATE_COUNT,
        "paths": manager.size(),
        "solver_calls": 0,
    }


def _bench_frontier_shadow_cegis_preview(*, solver_unsat: bool) -> dict[str, int]:
    """Benchmark explicit shadow CEGIS preview over live checkpoint capsules."""
    from pysymex._internal.execution.scheduling.cegis.evaluation.frontier import (
        evaluate_shadow_frontier,
    )

    checkpoints = _frontier_cegis_preview_checkpoints(solver_unsat=solver_unsat)
    live_state_ids = tuple(checkpoints.keys())
    capsules_by_state_id = {
        state_id: checkpoint.capsule for state_id, checkpoint in checkpoints.items()
    }
    preview_count = (
        _FRONTIER_CEGIS_SOLVER_ITERATIONS if solver_unsat else _FRONTIER_CEGIS_PREVIEW_ITERATIONS
    )
    removable_preview_count = 0
    for _ in range(preview_count):
        evaluation = evaluate_shadow_frontier(
            active_budget=_frontier_cegis_preview_budget(),
            live_state_ids=live_state_ids,
            capsules_by_state_id=capsules_by_state_id,
            checkpoints_by_state_id=checkpoints,
        )
        if evaluation.can_remove:
            removable_preview_count += 1

    expected_removable_count = preview_count if solver_unsat else 0
    if removable_preview_count != expected_removable_count:
        msg = (
            "CEGIS preview benchmark observed unexpected removable preview count: "
            f"expected {expected_removable_count}, got {removable_preview_count}"
        )
        raise RuntimeError(
            msg,
        )
    return {
        "instructions": preview_count,
        "paths": len(checkpoints),
        "solver_calls": preview_count if solver_unsat else 0,
        "solver_unsat": preview_count if solver_unsat else 0,
    }


def _frontier_cegis_preview_budget() -> BudgetVector:
    """Return a generous budget for isolated CEGIS preview benchmarking."""
    from pysymex._internal.execution.scheduling.cegis.budgets import BudgetVector

    return BudgetVector(
        wall_time_ms=1000.0,
        solver_time_ms=1000.0,
        resident_units=10000,
        reconstruction_units=10000,
        path_budget=1000,
    )


def _frontier_checkpoint_count(stats: dict[str, object]) -> int:
    """Extract the shadow checkpoint count from frontier stats."""
    raw_shadow_stats: object = stats.get("shadow_frontier")
    if not isinstance(raw_shadow_stats, Mapping):
        return 0
    shadow_stats = cast("Mapping[object, object]", raw_shadow_stats)
    raw_checkpoint_count = shadow_stats.get("checkpoint_count", 0)
    if isinstance(raw_checkpoint_count, bool):
        return 0
    if isinstance(raw_checkpoint_count, int):
        return raw_checkpoint_count
    return 0


def _build_frontier_admission_graph() -> ConstraintInteractionGraph:
    """Build a deterministic branch graph used by frontier admission benchmarks."""
    from pysymex._internal.core.graph.cig import ConstraintInteractionGraph

    cig = ConstraintInteractionGraph()
    for pc in range(_FRONTIER_ADMISSION_PC_COUNT):
        cig.add_branch(pc, {f"v{pc % 8}", f"shared{pc % 4}"})
    return cig


def _frontier_admission_states() -> list[VMState]:
    """Build representative queued states for frontier admission benchmarks."""
    import z3

    from pysymex._internal.core.state.record import VMState

    symbols = tuple(z3.Int(f"frontier_admission_{index}") for index in range(24))
    states: list[VMState] = []
    for state_index in range(_FRONTIER_ADMISSION_STATE_COUNT):
        constraints = [
            symbols[index] >= state_index % (index + 2)
            for index in range(_FRONTIER_ADMISSION_CONSTRAINT_COUNT)
        ]
        local_vars: dict[str, StackValue] = {
            f"v{index}": symbols[index] + state_index
            for index in range(_FRONTIER_ADMISSION_LOCAL_COUNT)
        }
        state = VMState(
            stack=[symbols[state_index % len(symbols)]],
            local_vars=local_vars,
            path_constraints=constraints,
            pc=state_index % _FRONTIER_ADMISSION_PC_COUNT,
            visited_pcs={state_index % _FRONTIER_ADMISSION_PC_COUNT},
            path_id=state_index + 1,
            depth=state_index % 64,
            pending_constraint_count=len(constraints),
        )
        states.append(state)
    return states


def _frontier_cegis_preview_checkpoints(
    *,
    solver_unsat: bool,
) -> dict[int, FrontierCheckpoint]:
    """Build compact checkpoints for CEGIS preview benchmark cases."""
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.frontier.checkpoints import build_frontier_checkpoint

    state_count = (
        _FRONTIER_CEGIS_SOLVER_STATE_COUNT if solver_unsat else _FRONTIER_CEGIS_PREVIEW_STATE_COUNT
    )
    checkpoints: dict[int, FrontierCheckpoint] = {}
    for state_id in range(state_count):
        constraints = []
        if solver_unsat:
            symbol = z3.Int(f"frontier_cegis_preview_{state_id}")
            constraints = [symbol > state_id, symbol <= state_id]
        state = VMState(
            path_constraints=constraints,
            pc=state_id % _FRONTIER_ADMISSION_PC_COUNT,
            path_id=state_id + 1,
            depth=state_id % 32,
            pending_constraint_count=len(constraints),
        )
        checkpoints[state_id] = build_frontier_checkpoint(state, capsule_id=f"path:{state_id}")
    return checkpoints
