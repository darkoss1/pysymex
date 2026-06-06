"""Tests for pysymex.tracing.tracer.proxy — TracingSolverProxy telemetry."""

from __future__ import annotations

import z3

from pysymex.core.solver.engine.results import SolverResult
from pysymex.tracing.tracer.proxy import TracingSolverProxy


class _InnerSolver:
    """Fake solver for testing TracingSolverProxy."""

    def __init__(self) -> None:
        self._cache_hits = 0
        self.pushed = 0
        self.custom_attr = ""
        self.new_val = 0

    def check(self, *_: z3.BoolRef, need_model: bool = True) -> z3.CheckSatResult:
        self._cache_hits += 1
        return z3.sat

    def push(self) -> None:
        self.pushed += 1

    def pop(self) -> None:
        self.pushed -= 1

    def add(self, *_: z3.BoolRef) -> None:
        return None

    def reset(self) -> None:
        self.pushed = 0

    def path_may_be_feasible(
        self, constraints: object, known_sat_prefix_len: int | None = None
    ) -> bool:
        return bool(constraints) or known_sat_prefix_len is None

    def check_sat_result(
        self,
        constraints: object,
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        return (
            SolverResult.sat(None)
            if self.path_may_be_feasible(constraints, known_sat_prefix_len)
            else SolverResult.unsat()
        )

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        return self.check_sat_result(constraints)

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        solver = z3.Solver()
        solver.add(*constraints)
        if solver.check() != z3.sat:
            return None
        return solver.model()

    def get_stats(self) -> dict[str, object]:
        return {"hits": self._cache_hits}

    def constraint_optimizer(self) -> object:
        return "optimizer"

    def set_deadline(self, deadline_time: float | None) -> None:
        _ = deadline_time


class _Tracer:
    """Fake tracer for testing TracingSolverProxy."""

    def __init__(self) -> None:
        self.calls = 0
        self.last_result: str | None = None

    def on_solve(
        self,
        constraints: list[z3.BoolRef],
        result_str: str,
        latency_ms: float,
        cache_hit: bool,
        model: object,
        path_id: int = 0,
        pc: int = 0,
    ) -> None:
        _ = constraints, latency_ms, cache_hit, model, path_id, pc
        self.calls += 1
        self.last_result = result_str


class TestTracingSolverProxy:
    """Tests for TracingSolverProxy delegation and telemetry."""

    def _proxy(
        self,
        inner: _InnerSolver | None = None,
        tracer: _Tracer | None = None,
    ) -> tuple[TracingSolverProxy, _InnerSolver, _Tracer]:
        solver = inner if inner is not None else _InnerSolver()
        telemetry = tracer if tracer is not None else _Tracer()
        return TracingSolverProxy(solver, telemetry, lambda: None), solver, telemetry

    def test_check_delegates_and_returns_result(self) -> None:
        """check() returns the inner solver result."""
        proxy, _, _ = self._proxy()
        result = proxy.check()
        assert result == z3.sat

    def test_check_emits_telemetry(self) -> None:
        """check() fires on_solve on the tracer."""
        proxy, _, tracer = self._proxy()
        proxy.check()
        assert tracer.calls == 1
        assert tracer.last_result == "sat"

    def test_push_pop_delegates(self) -> None:
        """push() and pop() delegate to inner solver."""
        proxy, inner, _ = self._proxy()
        proxy.push()
        assert inner.pushed == 1
        proxy.pop()
        assert inner.pushed == 0

    def test_add_delegates(self) -> None:
        """add() delegates to inner solver."""
        proxy, _, _ = self._proxy()
        proxy.add()  # Should not raise

    def test_reset_delegates(self) -> None:
        """reset() delegates to inner solver."""
        proxy, inner, _ = self._proxy()
        inner.pushed = 5
        proxy.reset()
        assert inner.pushed == 0

    def test_get_stats_delegates(self) -> None:
        """get_stats() delegates to inner solver."""
        proxy, _, _ = self._proxy()
        proxy.check()
        stats = proxy.get_stats()
        assert stats["hits"] == 1

    def test_constraint_optimizer_delegates(self) -> None:
        """constraint_optimizer() delegates to inner solver."""
        proxy, _, _ = self._proxy()
        assert proxy.constraint_optimizer() == "optimizer"

    def test_path_may_be_feasible_delegates(self) -> None:
        """path_may_be_feasible() delegates and emits telemetry."""
        proxy, _, tracer = self._proxy()
        result = proxy.path_may_be_feasible([z3.BoolVal(True)])
        assert result is True
        assert tracer.calls == 1

    def test_check_sat_result_delegates(self) -> None:
        """check_sat_result() delegates and preserves structured solver result."""
        proxy, _, tracer = self._proxy()
        result = proxy.check_sat_result([z3.BoolVal(True)])
        assert result.is_sat is True
        assert tracer.calls == 1
        assert tracer.last_result == "sat"

    def test_getattr_delegates(self) -> None:
        """Unknown attributes are delegated to inner solver."""
        inner = _InnerSolver()
        inner.custom_attr = "custom_value"
        proxy, _, _ = self._proxy(inner=inner)
        assert proxy.custom_attr == "custom_value"

    def test_setattr_delegates(self) -> None:
        """Setting attributes delegates to inner solver."""
        proxy, inner, _ = self._proxy()
        proxy.new_val = 42
        assert inner.new_val == 42
