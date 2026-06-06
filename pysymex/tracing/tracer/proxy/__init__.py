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

"""SMT solver proxy for tracking latency, cache hit ratios, and solver results."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, TypeVar

import z3

from pysymex.tracing.tracer.proxy.telemetry import (
    SolverTelemetrySink,
    TraceStateGetter,
    cache_hits_for,
    emit_solver_telemetry,
    solver_result_name,
    z3_check_result_name,
)
from pysymex.tracing.tracer.proxy.delegation import SolverDelegationMixin

if TYPE_CHECKING:
    from pysymex.typing import SolverProtocol
from pysymex.core.solver.engine.results import SolverResult


SolverCallResult = TypeVar("SolverCallResult")


class TracingSolverProxy(SolverDelegationMixin):
    """Transparent proxy around :class:`~pysymex.core.solver.IncrementalSolver`.

    Intercepts ``path_may_be_feasible`` and ``check`` method calls to measure solver latency
    and detect cache hits, then fires :meth:`ExecutionTracer.on_solve`.  Every
    other attribute access is delegated to the wrapped instance unchanged.

    Args:
        inner:        The real :class:`~pysymex.core.solver.IncrementalSolver`.
        tracer:       The :class:`ExecutionTracer` that receives ``on_solve``
                      notifications.
        state_getter: Zero-argument callable that returns the *current*
                      :class:`~pysymex.core.state.record.VMState`, used to embed
                      ``path_id`` and ``pc`` in solver events without the
                      proxy needing a direct reference to a mutable state.

    Safety contract
    ~~~~~~~~~~~~~~~
    * Any exception raised inside the proxy's interception logic is caught and
      written to ``stderr``.  The actual solver result is **always** returned
      to the caller unchanged — the proxy never interferes with correctness.
    * The proxy does not store or copy constraint objects beyond the duration
      of the call, preventing memory leaks on long analyses.
    """

    def __init__(
        self,
        inner: SolverProtocol,
        tracer: SolverTelemetrySink,
        state_getter: TraceStateGetter,
    ) -> None:
        """Initialize the proxy with a solver, tracer, and state provider."""
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_tracer", tracer)
        object.__setattr__(self, "_state_getter", state_getter)

    def _with_solver_telemetry(
        self,
        *,
        constraints: Iterable[z3.BoolRef],
        invoke: Callable[[], SolverCallResult],
        result_name: Callable[[SolverCallResult], str],
        model_for_result: Callable[[SolverCallResult], object] | None = None,
        method_name: str,
    ) -> SolverCallResult:
        """Run an intercepted solver call and emit the standard telemetry event."""
        inner: SolverProtocol = object.__getattribute__(self, "_inner")
        tracer: SolverTelemetrySink = object.__getattribute__(self, "_tracer")
        state_getter: TraceStateGetter = object.__getattribute__(self, "_state_getter")

        cache_hits_before = cache_hits_for(inner)
        t0 = time.perf_counter()

        result = invoke()
        latency_ms = (time.perf_counter() - t0) * 1000.0
        cache_hits_after = cache_hits_for(inner)
        cache_hit = cache_hits_after > cache_hits_before
        model = model_for_result(result) if model_for_result is not None else None

        emit_solver_telemetry(
            tracer=tracer,
            state_getter=state_getter,
            constraints=constraints,
            result_str=result_name(result),
            latency_ms=latency_ms,
            cache_hit=cache_hit,
            model=model,
            method_name=method_name,
        )

        return result

    def check(self, *assumptions: z3.BoolRef, need_model: bool = True) -> z3.CheckSatResult:
        """Intercept check (used by several internal callers), record telemetry."""
        inner: SolverProtocol = object.__getattribute__(self, "_inner")

        result = self._with_solver_telemetry(
            constraints=assumptions,
            invoke=(
                lambda: (
                    inner.check(*assumptions, need_model=need_model)
                    if assumptions
                    else inner.check(need_model=need_model)
                )
            ),
            result_name=z3_check_result_name,
            method_name="check",
        )

        if isinstance(result, z3.CheckSatResult):
            return result
        if hasattr(result, "is_sat") and bool(getattr(result, "is_sat", False)):
            return z3.sat
        if hasattr(result, "is_unsat") and bool(getattr(result, "is_unsat", False)):
            return z3.unsat
        return z3.unknown

    def path_may_be_feasible(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        """Intercept path-feasibility checks and record telemetry."""
        inner: SolverProtocol = object.__getattribute__(self, "_inner")

        result = self._with_solver_telemetry(
            constraints=constraints,
            invoke=lambda: inner.path_may_be_feasible(
                constraints,
                known_sat_prefix_len=known_sat_prefix_len,
            ),
            result_name=lambda result: "sat" if result else "unsat",
            method_name="path_may_be_feasible",
        )

        return result

    def check_sat_result(
        self,
        constraints: Iterable[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        """Intercept result-preserving SAT checks, record telemetry."""
        inner: SolverProtocol = object.__getattribute__(self, "_inner")

        return self._with_solver_telemetry(
            constraints=constraints,
            invoke=lambda: inner.check_sat_result(
                constraints,
                known_sat_prefix_len=known_sat_prefix_len,
            ),
            result_name=solver_result_name,
            model_for_result=lambda result: result.model,
            method_name="check_sat_result",
        )
