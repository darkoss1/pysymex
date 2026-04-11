from __future__ import annotations

from typing import cast
from unittest.mock import patch

import z3

from pysymex.accel.backends import BackendInfo, BackendType
from pysymex.accel.bytecode import compile_constraint
from pysymex.accel.dispatcher import evaluate_bag
from pysymex.accel.chtd_integration import (
    GPUBagEvaluator,
    get_bag_evaluator,
    is_gpu_available,
    reset,
)


def test_is_gpu_available_reflects_initializer() -> None:
    with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
        assert is_gpu_available() is False


class TestGPUBagEvaluator:
    def test_is_available_and_backend_info_when_unavailable(self) -> None:
        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
            evaluator = GPUBagEvaluator(gpu_threshold=1, warmup=False)

        assert evaluator.is_available is False
        assert evaluator.get_backend_info() == {"available": False}

    def test_should_use_gpu_threshold_and_bounds(self) -> None:
        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
            evaluator = GPUBagEvaluator(gpu_threshold=3, warmup=False)

        assert evaluator.should_use_gpu(5) is False

    def test_evaluate_bag_returns_none_when_not_using_gpu(self) -> None:
        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
            evaluator = GPUBagEvaluator(gpu_threshold=0, warmup=False)

        bitmap = evaluator.evaluate_bag([z3.BoolVal(True)], ["x"])
        assert bitmap is None

    def test_evaluate_bag_with_timeout_skips_when_estimate_exceeds_limit(self) -> None:
        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
            evaluator = GPUBagEvaluator(gpu_threshold=0, warmup=False)

        with patch.object(evaluator, "_estimate_execution_time", return_value=9999.0):
            bitmap = evaluator.evaluate_bag_with_timeout([z3.BoolVal(True)], ["x", "y"], timeout_ms=1.0)

        assert bitmap is None

    def test_count_satisfying_iter_and_list(self) -> None:
        tautology = compile_constraint(z3.BoolVal(True), ["x", "y"])
        bitmap = evaluate_bag(tautology).bitmap

        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=False):
            evaluator = GPUBagEvaluator(gpu_threshold=0, warmup=False)

        count = evaluator.count_satisfying(bitmap)
        items = list(evaluator.iter_satisfying(bitmap, ["x", "y"]))
        as_list = evaluator.get_satisfying_list(bitmap, ["x", "y"])

        assert count == 4
        assert len(items) == 4
        assert as_list == items

    def test_get_backend_info_when_gpu_ready(self) -> None:
        from pysymex.accel import bytecode, dispatcher

        info = BackendInfo(
            backend_type=BackendType.CPU,
            name="CPU",
            available=True,
            max_treewidth=12,
            supports_async=False,
        )

        class _FakeDispatcher:
            def get_backend_info(self) -> BackendInfo:
                return info

            def evaluate_bag(self, compiled: object) -> object:
                return evaluate_bag(compiled)

        with patch("pysymex.accel.chtd_integration._init_gpu", return_value=True):
            with patch("pysymex.accel.chtd_integration._gpu_module", (bytecode, dispatcher)):
                with patch("pysymex.accel.dispatcher.get_dispatcher", return_value=_FakeDispatcher()):
                    evaluator = GPUBagEvaluator(gpu_threshold=0, warmup=False)

        backend = evaluator.get_backend_info()
        assert cast("bool", backend["available"]) is True
        assert backend["name"] == "CPU"
        assert int(cast("int", backend["max_treewidth"])) == 12


def test_get_bag_evaluator_singleton_and_reset() -> None:
    reset()
    e0 = get_bag_evaluator(gpu_threshold=5)
    e1 = get_bag_evaluator(gpu_threshold=99)
    assert e0 is e1

    reset()
    e2 = get_bag_evaluator(gpu_threshold=5)
    assert e2 is not e0
