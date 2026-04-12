from __future__ import annotations

from typing import Any, cast

import z3

from pysymex.tracing.tracer import TracingSolverProxy


class _InnerSolver:
    def __init__(self) -> None:
        self._cache_hits = 0
        self.pushed = 0

    def check(self, *_: object) -> z3.CheckSatResult:
        self._cache_hits += 1
        return z3.sat

    def push(self) -> None:
        self.pushed += 1

    def pop(self) -> None:
        self.pushed -= 1

    def add(self, *_: object) -> None:
        return None

    def reset(self) -> None:
        self.pushed = 0

    def is_sat(self, constraints: object, known_sat_prefix_len: int | None = None) -> bool:
        return bool(constraints) or known_sat_prefix_len is None

    def get_stats(self) -> dict[str, object]:
        return {"hits": self._cache_hits}

    def constraint_optimizer(self) -> object:
        return "optimizer"


class _Tracer:
    def __init__(self) -> None:
        self.calls = 0

    def on_solve(self, **_: object) -> None:
        self.calls += 1


class _State:
    path_id = 1
    pc = 2


def test_tracing_solver_proxy_delegates_and_emits_telemetry() -> None:
    inner = _InnerSolver()
    tracer = _Tracer()
    proxy = TracingSolverProxy(
        cast("Any", inner),
        cast("Any", tracer),
        cast("Any", (lambda: _State())),
    )

    result = proxy.check()
    proxy.push()
    proxy.pop()

    assert result == z3.sat
    assert tracer.calls == 1
    assert proxy.get_stats()["hits"] == 1
    assert proxy.constraint_optimizer() == "optimizer"

