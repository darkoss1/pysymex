from __future__ import annotations

import numpy as np
import z3

from pysymex.accel.backends import BackendType
from pysymex.accel.bytecode import compile_constraint
from pysymex.accel.dispatcher import (
    DispatchResult,
    TieredDispatcher,
    _mask_unused_tail_bits,  # type: ignore[reportPrivateUsage]  # testing private helper
    count_satisfying,
    evaluate_bag,
    get_backend_info,
    get_dispatcher,
    iter_satisfying,
    reset,
    warmup,
)


class TestDispatchResult:
    def test_count_satisfying_caches_non_negative_value(self) -> None:
        reset()
        x, y = z3.Bools("x y")
        constraint = compile_constraint(z3.Or(x, y), ["x", "y"])
        result = evaluate_bag(constraint)

        assert isinstance(result, DispatchResult)
        assert result.count_satisfying() == 3
        assert result.count_satisfying() == 3


class TestTieredDispatcher:
    def test_selected_backend_is_valid_backend_type(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        assert dispatcher.selected_backend in {
            BackendType.SAT,
            BackendType.CPU,
            BackendType.REFERENCE,
        }

    def test_get_backend_info_matches_selected_backend(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        info = dispatcher.get_backend_info()
        assert info.backend_type is dispatcher.selected_backend

    def test_list_backends_and_backend_items_not_empty(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        infos = dispatcher.list_backends()
        items = dispatcher.backend_items()
        assert len(infos) >= 1
        assert len(items) >= 1

    def test_evaluate_bag_returns_result_and_updates_routing_stats(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        x, y = z3.Bools("x y")
        constraint = compile_constraint(z3.And(x, y), ["x", "y"])
        result = dispatcher.evaluate_bag(constraint)

        assert isinstance(result, DispatchResult)
        assert result.backend_used in {
            BackendType.SAT,
            BackendType.CPU,
            BackendType.REFERENCE,
        }
        stats = dispatcher.get_routing_stats()
        decisions_obj = stats["routing_decisions"]
        assert isinstance(decisions_obj, dict)
        assert result.backend_used.name in decisions_obj

    def test_get_routing_stats_contains_expected_keys(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        stats = dispatcher.get_routing_stats()
        assert "selected_backend" in stats
        assert "routing_decisions" in stats
        assert "latency_ewma_ms" in stats
        assert "guardrail_fallbacks" in stats

    def test_evaluate_bag_with_fallback_produces_dispatch_result(self) -> None:
        reset()
        dispatcher = TieredDispatcher()
        x = z3.Bool("x")
        constraint = compile_constraint(x, ["x"])
        result = dispatcher.evaluate_bag_with_fallback(constraint)
        assert isinstance(result, DispatchResult)


def test_get_dispatcher_reset_and_singleton_behavior() -> None:
    reset()
    d1 = get_dispatcher()
    d2 = get_dispatcher()
    assert d1 is d2
    reset()
    d3 = get_dispatcher()
    assert d3 is not d1


def test_module_evaluate_bag_and_get_backend_info() -> None:
    reset()
    dispatcher = get_dispatcher()
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.And(x, y), ["x", "y"])
    result = evaluate_bag(constraint)
    info = get_backend_info()

    assert info.backend_type is dispatcher.selected_backend
    assert result.backend_used in {
        backend_info.backend_type
        for backend_info in dispatcher.list_backends()
        if backend_info.available
    }


def test_count_satisfying_and_iter_satisfying_match_expected_assignments() -> None:
    reset()
    x, y = z3.Bools("x y")
    constraint = compile_constraint(z3.Or(x, y), ["x", "y"])
    result = evaluate_bag(constraint)

    assert count_satisfying(result.bitmap) == 3
    assignments = list(iter_satisfying(result.bitmap, 2, ["x", "y"]))
    assert len(assignments) == 3
    assert {tuple(sorted(a.items())) for a in assignments} == {
        (("x", True), ("y", False)),
        (("x", False), ("y", True)),
        (("x", True), ("y", True)),
    }


def test_warmup_and_reset_are_safe_to_call() -> None:
    reset()
    assert warmup() is None
    assert reset() is None


def test_mask_unused_tail_bits_zeroes_padding() -> None:
    masked = _mask_unused_tail_bits(np.frombuffer(b"\xff", dtype=np.uint8), 3)  # type: ignore[reportPrivateUsage]
    assert int(masked[0]) == 0b00000111
