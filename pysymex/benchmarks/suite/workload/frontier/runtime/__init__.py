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

"""Runtime CEGIS frontier benchmark workloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex.core.graph.cig import ConstraintInteractionGraph
    from pysymex.core.state.record import VMState
    from pysymex.execution.strategies.manager.path import AdaptivePathManager

_FRONTIER_RUNTIME_CEGIS_STATE_COUNT = 64
_FRONTIER_RUNTIME_PC_COUNT = 32
_FRONTIER_RUNTIME_PRESSURE_STATE_COUNT = 1100
_FRONTIER_RUNTIME_PRESSURE_LOCAL_COUNT = 8

__all__ = [
    "bench_frontier_runtime_cegis_core_reuse_pruning",
    "bench_frontier_runtime_cegis_dominance_pruning",
    "bench_frontier_runtime_cegis_exact_pruning",
    "bench_frontier_runtime_pressure_compaction",
]


def bench_frontier_runtime_cegis_exact_pruning() -> dict[str, int]:
    """Benchmark: Explicit runtime CEGIS exact UNSAT pruning plus execute selection."""
    return _bench_frontier_runtime_cegis(
        states=_frontier_runtime_cegis_unsat_states(),
        expected_removed=_FRONTIER_RUNTIME_CEGIS_STATE_COUNT // 2,
        solver_owned=True,
    )


def bench_frontier_runtime_cegis_dominance_pruning() -> dict[str, int]:
    """Benchmark: Explicit runtime CEGIS duplicate pruning plus execute selection."""
    return _bench_frontier_runtime_cegis(
        states=_frontier_runtime_cegis_dominance_states(),
        expected_removed=_FRONTIER_RUNTIME_CEGIS_STATE_COUNT // 2,
        solver_owned=False,
    )


def bench_frontier_runtime_cegis_core_reuse_pruning() -> dict[str, int]:
    """Benchmark: Explicit runtime CEGIS UNSAT-core reuse across live checkpoints."""
    return _bench_frontier_runtime_cegis(
        states=_frontier_runtime_cegis_core_reuse_states(),
        expected_removed=_FRONTIER_RUNTIME_CEGIS_STATE_COUNT,
        solver_owned=True,
    )


def bench_frontier_runtime_pressure_compaction() -> dict[str, int]:
    """Benchmark: Default-threshold POLAR runtime pressure compaction."""
    from pysymex.execution.frontier import FrontierRuntimeMode
    from pysymex.execution.strategies.manager.path import AdaptivePathManager

    manager = AdaptivePathManager(
        _build_frontier_runtime_graph(),
        deterministic=True,
        random_seed=7,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    for state in _frontier_runtime_pressure_states():
        manager.add_state(state)

    shadow_stats = _shadow_frontier_stats(manager.get_stats())
    pressure_compactions = _shadow_stats_int(shadow_stats, "pressure_compaction_count")
    pressure_triggers = _shadow_stats_int(shadow_stats, "pressure_compaction_trigger_count")
    compacted_entries = _shadow_stats_int(shadow_stats, "compacted_entry_count")
    resident_units = _shadow_stats_int(shadow_stats, "runtime_estimated_resident_units")

    if pressure_triggers <= 0 or pressure_compactions <= 0:
        raise RuntimeError(
            "pressure compaction benchmark did not cross the default runtime threshold"
        )
    if compacted_entries != pressure_compactions:
        raise RuntimeError(
            "pressure compaction benchmark observed inconsistent compaction counters: "
            f"frontier={compacted_entries}, pressure={pressure_compactions}"
        )
    return {
        "instructions": _FRONTIER_RUNTIME_PRESSURE_STATE_COUNT,
        "paths": manager.size(),
        "solver_calls": 0,
        "pressure_triggers": pressure_triggers,
        "pressure_compactions": pressure_compactions,
        "compacted_entries": compacted_entries,
        "resident_units": resident_units,
    }


def _bench_frontier_runtime_cegis(
    *,
    states: list["VMState"],
    expected_removed: int,
    solver_owned: bool,
) -> dict[str, int]:
    """Benchmark runtime CEGIS removal through the path manager."""
    from pysymex.execution.frontier import FrontierRuntimeMode
    from pysymex.execution.strategies.manager.path import AdaptivePathManager

    manager = AdaptivePathManager(
        _build_frontier_runtime_graph(),
        deterministic=True,
        random_seed=7,
        frontier_runtime_mode=FrontierRuntimeMode.POLAR_CEGIS_RUNTIME,
    )
    for state in states:
        manager.add_state(state)

    removed_state_count, preview_count = _apply_explicit_cegis(manager)

    selected_states = 0
    while not manager.is_empty():
        state = manager.get_next_state()
        if state is not None:
            selected_states += 1

    if removed_state_count != expected_removed:
        raise RuntimeError(
            "runtime CEGIS benchmark observed unexpected exact-prune count: "
            f"expected {expected_removed}, got {removed_state_count}"
        )
    metrics = {
        "instructions": selected_states + removed_state_count,
        "paths": selected_states,
        "solver_calls": 0,
        "solver_sat": 0,
        "solver_unsat": 0,
    }
    if solver_owned:
        metrics["solver_calls"] = preview_count
        metrics["solver_sat"] = 0
        metrics["solver_unsat"] = max(0, metrics["solver_calls"] - metrics["solver_sat"])
    return metrics


def _shadow_frontier_stats(stats: dict[str, object]) -> Mapping[object, object]:
    """Return typed shadow frontier stats from path-manager diagnostics."""
    raw_shadow_stats = stats.get("shadow_frontier")
    if isinstance(raw_shadow_stats, Mapping):
        return cast("Mapping[object, object]", raw_shadow_stats)
    msg = "path manager did not expose shadow frontier benchmark stats"
    raise RuntimeError(msg)


def _shadow_stats_int(stats: Mapping[object, object], key: str) -> int:
    """Return one integer shadow-frontier stat."""
    value = stats.get(key)
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    msg = f"shadow frontier stat {key!r} is not an integer"
    raise RuntimeError(msg)


def _apply_explicit_cegis(manager: "AdaptivePathManager") -> tuple[int, int]:
    """Apply explicit CEGIS preview/apply cycles until no more work can be removed."""
    from pysymex.execution.scheduling.cegis import BudgetVector

    removed_state_count = 0
    preview_count = 0
    remaining_attempts = max(1, manager.size())
    budget = BudgetVector(
        wall_time_ms=1000.0,
        solver_time_ms=1000.0,
        resident_units=10000,
        reconstruction_units=10000,
        path_budget=1000,
    )
    while manager.size() > 0 and remaining_attempts > 0:
        evaluation = manager.preview_shadow_cegis_frontier(budget)
        preview_count += 1
        outcome = evaluation.outcome
        if outcome is None or not evaluation.can_remove:
            break
        removed_now = manager.apply_evidence_outcome(outcome)
        if removed_now <= 0:
            break
        removed_state_count += removed_now
        remaining_attempts -= removed_now
    return removed_state_count, preview_count


def _frontier_runtime_cegis_unsat_states() -> list["VMState"]:
    """Build mixed SAT/UNSAT states for runtime exact-pruning benchmarks."""
    import z3

    from pysymex.core.state.record import VMState

    states: list[VMState] = []
    for state_index in range(_FRONTIER_RUNTIME_CEGIS_STATE_COUNT):
        symbol = z3.Int(f"frontier_runtime_cegis_{state_index}")
        constraints = [symbol > state_index]
        if state_index % 2 == 0:
            constraints.append(symbol <= state_index)
        states.append(
            VMState(
                path_constraints=constraints,
                pc=state_index % _FRONTIER_RUNTIME_PC_COUNT,
                path_id=state_index + 1,
                depth=state_index % 32,
                pending_constraint_count=len(constraints),
            )
        )
    return states


def _frontier_runtime_cegis_dominance_states() -> list["VMState"]:
    """Build structurally duplicate state pairs for runtime dominance benchmarks."""
    from pysymex.core.state.record import VMState

    states: list[VMState] = []
    pair_count = _FRONTIER_RUNTIME_CEGIS_STATE_COUNT // 2
    for pair_index in range(pair_count):
        states.append(
            VMState(
                pc=pair_index % _FRONTIER_RUNTIME_PC_COUNT,
                path_id=pair_index + 1,
                depth=pair_index % 32,
            )
        )
        states.append(
            VMState(
                pc=pair_index % _FRONTIER_RUNTIME_PC_COUNT,
                path_id=pair_index + 1,
                depth=pair_index % 32,
            )
        )
    return states


def _frontier_runtime_pressure_states() -> list["VMState"]:
    """Build enough runtime states to cross the production pressure threshold."""
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue

    states: list[VMState] = []
    for state_index in range(_FRONTIER_RUNTIME_PRESSURE_STATE_COUNT):
        local_vars: dict[str, StackValue] = {
            f"v{index}": (state_index * _FRONTIER_RUNTIME_PRESSURE_LOCAL_COUNT) + index
            for index in range(_FRONTIER_RUNTIME_PRESSURE_LOCAL_COUNT)
        }
        states.append(
            VMState(
                stack=[state_index],
                local_vars=local_vars,
                pc=state_index % _FRONTIER_RUNTIME_PC_COUNT,
                visited_pcs={state_index % _FRONTIER_RUNTIME_PC_COUNT},
                path_id=state_index + 1,
                depth=state_index % 64,
            )
        )
    return states


def _frontier_runtime_cegis_core_reuse_states() -> list["VMState"]:
    """Build paired UNSAT states with shared exact core constraints."""
    import z3

    from pysymex.core.state.record import VMState

    states: list[VMState] = []
    pair_count = _FRONTIER_RUNTIME_CEGIS_STATE_COUNT // 2
    for pair_index in range(pair_count):
        symbol = z3.Int(f"frontier_runtime_cegis_core_reuse_{pair_index}")
        positive = symbol > pair_index
        nonpositive = symbol <= pair_index
        states.append(
            VMState(
                path_constraints=[positive, nonpositive],
                pc=pair_index % _FRONTIER_RUNTIME_PC_COUNT,
                path_id=(pair_index * 2) + 1,
                depth=pair_index % 32,
                pending_constraint_count=2,
            )
        )
        states.append(
            VMState(
                path_constraints=[positive, nonpositive],
                pc=(pair_index + 1) % _FRONTIER_RUNTIME_PC_COUNT,
                path_id=(pair_index * 2) + 2,
                depth=(pair_index + 1) % 32,
                pending_constraint_count=2,
            )
        )
    return states


def _build_frontier_runtime_graph() -> "ConstraintInteractionGraph":
    """Build a deterministic branch graph used by runtime frontier benchmarks."""
    from pysymex.core.graph.cig import ConstraintInteractionGraph

    cig = ConstraintInteractionGraph()
    for pc in range(_FRONTIER_RUNTIME_PC_COUNT):
        cig.add_branch(pc, {f"v{pc % 8}", f"shared{pc % 4}"})
    return cig
