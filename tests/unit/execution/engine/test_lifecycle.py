"""Tests for engine-owned execution lifecycle reset."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.types.containers.bytes import BYTES_CONST_CACHE, SymbolicBytes
from pysymex._internal.core.types.scalars.value.scalar_ops import (
    FROM_CONST_CACHE,
    STRING_CONST_CACHE,
    SYMBOLIC_CACHE,
)
from pysymex._internal.execution.engine.lifecycle import reset_execution_run
from pysymex._internal.execution.session.state.core import ExecutionSession


class ResettableDouble:
    """Simple resettable collaborator for lifecycle tests."""

    def __init__(self) -> None:
        self.reset_calls = 0

    def reset(self) -> None:
        self.reset_calls += 1


class SolverDouble:
    """SolverProtocol-compatible double that records reset calls."""

    def __init__(self) -> None:
        self.reset_calls = 0

    def check(
        self,
        *assumptions: z3.BoolRef,
        need_model: bool = True,
    ) -> SolverResult | z3.CheckSatResult:
        _ = assumptions
        _ = need_model
        return SolverResult.sat(None)

    def push(self) -> None:
        return None

    def pop(self) -> None:
        return None

    def add(self, *constraints: z3.BoolRef) -> None:
        _ = constraints

    def reset(self) -> None:
        self.reset_calls += 1

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        _ = list(constraints)
        _ = known_sat_prefix_len
        return True

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = list(constraints)
        _ = known_sat_prefix_len
        return SolverResult.sat(None)

    def check_sat_cached(
        self,
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = constraints
        _ = known_sat_prefix_len
        return SolverResult.sat(None)

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        _ = constraints
        return None

    def get_stats(self) -> dict[str, object]:
        return {}

    def constraint_optimizer(self) -> object:
        return self

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


def _sample() -> int:
    return 1


def test_reset_execution_run_resets_session_and_sidecars() -> None:
    session = ExecutionSession()
    session.paths_explored = 4
    solver = SolverDouble()
    state_merger = ResettableDouble()
    resource_tracker = ResettableDouble()
    interaction_graph = ResettableDouble()

    reset_execution_run(
        solver=solver,
        session=session,
        infrastructure_degraded_passes=["infrastructure"],
        state_merger=state_merger,
        resource_tracker=resource_tracker,
        interaction_graph=interaction_graph,
    )

    assert solver.reset_calls == 2
    assert state_merger.reset_calls == 1
    assert resource_tracker.reset_calls == 1
    assert interaction_graph.reset_calls == 1
    assert session.paths_explored == 1
    assert session.degraded_passes == ["infrastructure"]


def test_reset_execution_run_preserves_immutable_instruction_cache() -> None:
    session = ExecutionSession()
    solver = SolverDouble()
    interaction_graph = ResettableDouble()
    SYMBOLIC_CACHE["unit"] = (object(), z3.BoolVal(True))
    FROM_CONST_CACHE["unit"] = z3.IntVal(1)
    STRING_CONST_CACHE["unit"] = z3.StringVal("unit")
    _ = SymbolicBytes.concrete(b"unit")
    _ = get_instructions(_sample.__code__)
    assert get_instructions.cache_info().currsize >= 1

    reset_execution_run(
        solver=solver,
        session=session,
        infrastructure_degraded_passes=[],
        state_merger=None,
        resource_tracker=None,
        interaction_graph=interaction_graph,
    )

    assert SYMBOLIC_CACHE == {}
    assert FROM_CONST_CACHE == {}
    assert STRING_CONST_CACHE == {}
    assert BYTES_CONST_CACHE == {}
    assert get_instructions.cache_info().currsize >= 1
