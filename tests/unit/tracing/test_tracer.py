"""Tests for pysymex.tracing.tracer — solver proxy, config helpers, execution tracer."""

from __future__ import annotations

import json
from typing import Any, cast

import z3

from pysymex.tracing.tracer import (
    ExecutionTracer,
    TracingSolverProxy,
    _normalise_config_snapshot,
    _to_config_scalar,
)
from pysymex.tracing.schemas import TracerConfig


class _InnerSolver:
    """Fake solver for testing TracingSolverProxy."""

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
    """Fake tracer for testing TracingSolverProxy."""

    def __init__(self) -> None:
        self.calls = 0
        self.last_result: str | None = None

    def on_solve(self, **kwargs: object) -> None:
        self.calls += 1
        self.last_result = str(kwargs.get("result_str", ""))


class _State:
    path_id = 1
    pc = 2


class TestToConfigScalar:
    """Tests for _to_config_scalar coercion."""

    def test_none_passthrough(self) -> None:
        """None passes through."""
        assert _to_config_scalar(None) is None

    def test_str_passthrough(self) -> None:
        """String passes through."""
        assert _to_config_scalar("hello") == "hello"

    def test_int_passthrough(self) -> None:
        """Int passes through."""
        assert _to_config_scalar(42) == 42

    def test_float_passthrough(self) -> None:
        """Float passes through."""
        assert _to_config_scalar(3.14) == 3.14

    def test_bool_passthrough(self) -> None:
        """Bool passes through."""
        assert _to_config_scalar(True) is True

    def test_bytes_decoded(self) -> None:
        """Bytes are decoded to string."""
        result = _to_config_scalar(b"hello")
        assert result == "hello"

    def test_dict_serialized(self) -> None:
        """Dict is JSON-serialized."""
        result = _to_config_scalar({"key": "value"})
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["key"] == "value"

    def test_list_serialized(self) -> None:
        """List is JSON-serialized."""
        result = _to_config_scalar([1, 2, 3])
        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed == [1, 2, 3]


class TestNormaliseConfigSnapshot:
    """Tests for _normalise_config_snapshot."""

    def test_scalar_values(self) -> None:
        """Scalar values pass through."""
        snapshot: dict[str, object] = {"timeout": 5000, "name": "test"}
        result = _normalise_config_snapshot(snapshot)
        assert result["timeout"] == 5000
        assert result["name"] == "test"

    def test_complex_values(self) -> None:
        """Complex values are serialized."""
        snapshot: dict[str, object] = {"nested": {"a": 1}}
        result = _normalise_config_snapshot(snapshot)
        assert isinstance(result["nested"], str)

    def test_empty_snapshot(self) -> None:
        """Empty dict produces empty result."""
        result = _normalise_config_snapshot({})
        assert result == {}


class TestTracingSolverProxy:
    """Tests for TracingSolverProxy delegation and telemetry."""

    def test_check_delegates_and_returns_result(self) -> None:
        """check() returns the inner solver result."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        result = proxy.check()
        assert result == z3.sat

    def test_check_emits_telemetry(self) -> None:
        """check() fires on_solve on the tracer."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        proxy.check()
        assert tracer.calls == 1
        assert tracer.last_result == "sat"

    def test_push_pop_delegates(self) -> None:
        """push() and pop() delegate to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        proxy.push()
        assert inner.pushed == 1
        proxy.pop()
        assert inner.pushed == 0

    def test_add_delegates(self) -> None:
        """add() delegates to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        proxy.add()  # Should not raise

    def test_reset_delegates(self) -> None:
        """reset() delegates to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        inner.pushed = 5
        proxy.reset()
        assert inner.pushed == 0

    def test_get_stats_delegates(self) -> None:
        """get_stats() delegates to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        proxy.check()
        stats = proxy.get_stats()
        assert stats["hits"] == 1

    def test_constraint_optimizer_delegates(self) -> None:
        """constraint_optimizer() delegates to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        assert proxy.constraint_optimizer() == "optimizer"

    def test_is_sat_delegates(self) -> None:
        """is_sat() delegates and emits telemetry."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        result = proxy.is_sat([z3.BoolVal(True)])
        assert result is True
        assert tracer.calls == 1

    def test_getattr_delegates(self) -> None:
        """Unknown attributes are delegated to inner solver."""
        inner = _InnerSolver()
        inner.custom_attr = "custom_value"  # type: ignore[attr-defined]
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        assert proxy.custom_attr == "custom_value"  # type: ignore[attr-defined]

    def test_setattr_delegates(self) -> None:
        """Setting attributes delegates to inner solver."""
        inner = _InnerSolver()
        tracer = _Tracer()
        proxy = TracingSolverProxy(
            cast("Any", inner),
            cast("Any", tracer),
            cast("Any", (lambda: _State())),
        )
        proxy.new_val = 42  # type: ignore[attr-defined]
        assert inner.new_val == 42  # type: ignore[attr-defined]


class TestExecutionTracer:
    """Tests for ExecutionTracer initialization and config."""

    def test_init_default_config(self) -> None:
        """ExecutionTracer initializes with default config."""
        tracer = ExecutionTracer()
        assert tracer._config is not None
        assert tracer._seq == 0
        assert tracer._file is None

    def test_init_custom_config(self) -> None:
        """ExecutionTracer accepts custom config."""
        config = TracerConfig(enabled=False)
        tracer = ExecutionTracer(config=config)
        assert tracer._config.enabled is False

    def test_registry_property(self) -> None:
        """registry property returns Z3SemanticRegistry."""
        tracer = ExecutionTracer()
        assert tracer.registry is not None

    def test_end_session_without_start(self) -> None:
        """end_session() on un-started tracer returns None."""
        tracer = ExecutionTracer(config=TracerConfig(enabled=False))
        result = tracer.end_session()
        assert result is None

    def test_context_manager(self) -> None:
        """ExecutionTracer works as context manager."""
        config = TracerConfig(enabled=False)
        with ExecutionTracer(config=config) as tracer:
            assert tracer._file is None
