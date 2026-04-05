"""Targeted CHTD smoke tests for executor integration.

These tests avoid full scan runtime and directly verify that the CHTD
message-passing hook is invoked (or skipped) in branch-processing.
"""

from __future__ import annotations

import z3
from _pytest.monkeypatch import MonkeyPatch

from pysymex.core.state import VMState
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.executor_types import ExecutionConfig


class _TestableSymbolicExecutor(SymbolicExecutor):
    def process_result(self, result: OpcodeResult, state: VMState) -> None:
        self._process_execution_result(result, state, active_instructions=[])

    def set_iterations(self, iterations: int) -> None:
        self._iterations = iterations

    @property
    def paths_pruned(self) -> int:
        return self._paths_pruned

    @property
    def current_chtd_interval(self) -> int:
        return self._current_chtd_interval

    @property
    def next_chtd_check_iteration(self) -> int:
        return self._next_chtd_check_iteration

    def collect_chtd_stats(self) -> dict[str, object]:
        return self._collect_chtd_stats()


class _FakeTreeDecomposition:
    def __init__(self) -> None:
        self.width = 1
        self.bags = [object()]


class _FakeInteractionGraph:
    def __init__(self) -> None:
        self.branch_info: dict[object, object] = {}
        self.added: list[tuple[int, z3.BoolRef]] = []
        self.stabilized = True

    def add_branch(self, pc: int, constraint: z3.BoolRef) -> None:
        self.added.append((pc, constraint))
        self.branch_info[pc] = constraint

    def is_stabilized(self) -> bool:
        return self.stabilized

    def compute_tree_decomposition(self) -> _FakeTreeDecomposition:
        return _FakeTreeDecomposition()


class _FakeSolver:
    def __init__(self, sat: bool) -> None:
        self.is_gpu_available = False
        self.sat = sat
        self.calls = 0

    def propagate_all(self, td: object, branch_info: object) -> bool:
        self.calls += 1
        return self.sat


def _forked_states() -> list[VMState]:
    return [
        VMState(pc=10, path_constraints=[z3.Bool("c_left")]),
        VMState(pc=20, path_constraints=[z3.Bool("c_right")]),
    ]


def _always_feasible(state: VMState) -> bool:
    _ = state
    return True


def test_chtd_hook_invoked_when_enabled(monkeypatch: MonkeyPatch) -> None:
    fake_solver = _FakeSolver(sat=False)

    def _fake_get_solver(*, use_gpu: bool) -> _FakeSolver:
        _ = use_gpu
        return fake_solver

    monkeypatch.setattr(
        "pysymex.execution.executor_core._get_chtd_solver",
        _fake_get_solver,
    )

    executor = _TestableSymbolicExecutor(
        config=ExecutionConfig(enable_chtd=True, enable_h_acceleration=False)
    )
    fake_graph = _FakeInteractionGraph()
    monkeypatch.setattr(executor, "_interaction_graph", fake_graph, raising=False)
    monkeypatch.setattr(executor, "_check_path_feasibility", _always_feasible, raising=False)

    result = OpcodeResult.branch(_forked_states())
    executor.process_result(result, VMState())
    stats = executor.collect_chtd_stats()

    assert fake_solver.calls == 1
    assert len(fake_graph.added) == 2
    # False UNSAT from CHTD must not prune feasible branches.
    assert executor.paths_pruned == 0
    assert stats["unsat_hits"] == 1
    assert stats["unsat_validations"] == 1
    assert stats["unsat_mismatches"] == 1


def test_chtd_hook_skipped_when_disabled(monkeypatch: MonkeyPatch) -> None:
    fake_solver = _FakeSolver(sat=True)

    def _fake_get_solver(*, use_gpu: bool) -> _FakeSolver:
        _ = use_gpu
        return fake_solver

    monkeypatch.setattr(
        "pysymex.execution.executor_core._get_chtd_solver",
        _fake_get_solver,
    )

    executor = _TestableSymbolicExecutor(
        config=ExecutionConfig(enable_chtd=False, enable_h_acceleration=False)
    )
    fake_graph = _FakeInteractionGraph()
    monkeypatch.setattr(executor, "_interaction_graph", fake_graph, raising=False)
    monkeypatch.setattr(executor, "_check_path_feasibility", _always_feasible, raising=False)

    result = OpcodeResult.branch(_forked_states())
    executor.process_result(result, VMState())

    assert fake_solver.calls == 0
    assert len(fake_graph.added) == 0


def test_chtd_adaptive_interval_reschedules_on_branch_growth(monkeypatch: MonkeyPatch) -> None:
    fake_solver = _FakeSolver(sat=True)

    def _fake_get_solver(*, use_gpu: bool) -> _FakeSolver:
        _ = use_gpu
        return fake_solver

    monkeypatch.setattr(
        "pysymex.execution.executor_core._get_chtd_solver",
        _fake_get_solver,
    )

    executor = _TestableSymbolicExecutor(
        config=ExecutionConfig(
            enable_chtd=True,
            enable_h_acceleration=False,
            chtd_check_interval=8,
            chtd_adaptive_interval=True,
            chtd_min_check_interval=2,
            chtd_max_check_interval=16,
            chtd_growth_trigger=2,
        )
    )
    fake_graph = _FakeInteractionGraph()
    monkeypatch.setattr(executor, "_interaction_graph", fake_graph, raising=False)
    monkeypatch.setattr(executor, "_check_path_feasibility", _always_feasible, raising=False)
    executor.set_iterations(10)

    result = OpcodeResult.branch(_forked_states())
    executor.process_result(result, VMState())

    assert fake_solver.calls == 1
    assert executor.current_chtd_interval == 4
    assert executor.next_chtd_check_iteration == 14


def test_chtd_telemetry_counters_update_when_solver_unavailable(monkeypatch: MonkeyPatch) -> None:
    def _fake_get_solver(*, use_gpu: bool) -> None:
        _ = use_gpu
        return None

    monkeypatch.setattr(
        "pysymex.execution.executor_core._get_chtd_solver",
        _fake_get_solver,
    )

    executor = _TestableSymbolicExecutor(
        config=ExecutionConfig(enable_chtd=True, enable_h_acceleration=False)
    )
    fake_graph = _FakeInteractionGraph()
    monkeypatch.setattr(executor, "_interaction_graph", fake_graph, raising=False)
    monkeypatch.setattr(executor, "_check_path_feasibility", _always_feasible, raising=False)

    result = OpcodeResult.branch(_forked_states())
    executor.process_result(result, VMState())
    stats = executor.collect_chtd_stats()

    assert stats["solver_unavailable"] == 1
    assert stats["runs"] == 0
    assert isinstance(stats["total_time_seconds"], float)


def test_chtd_unsat_prune_kept_when_incremental_solver_agrees(monkeypatch: MonkeyPatch) -> None:
    fake_solver = _FakeSolver(sat=False)

    def _fake_get_solver(*, use_gpu: bool) -> _FakeSolver:
        _ = use_gpu
        return fake_solver

    monkeypatch.setattr(
        "pysymex.execution.executor_core._get_chtd_solver",
        _fake_get_solver,
    )

    executor = _TestableSymbolicExecutor(
        config=ExecutionConfig(enable_chtd=True, enable_h_acceleration=False)
    )
    fake_graph = _FakeInteractionGraph()
    monkeypatch.setattr(executor, "_interaction_graph", fake_graph, raising=False)
    monkeypatch.setattr(executor, "_check_path_feasibility", _always_feasible, raising=False)

    def _always_unsat(constraints: list[z3.BoolRef], known_sat_prefix_len: int | None = None) -> bool:
        _ = constraints
        _ = known_sat_prefix_len
        return False

    monkeypatch.setattr(executor.solver, "is_sat", _always_unsat)

    result = OpcodeResult.branch(_forked_states())
    executor.process_result(result, VMState())
    stats = executor.collect_chtd_stats()

    assert fake_solver.calls == 1
    assert executor.paths_pruned >= 2
    assert stats["unsat_hits"] == 1
    assert stats["unsat_validations"] == 1
    assert stats["unsat_mismatches"] == 0
