from __future__ import annotations

from concurrent.futures import Future
from unittest.mock import patch

import numpy as np
import numpy.typing as npt
import z3

from pysymex.accel.async_exec import (
    AsyncGPUExecutor,
    AsyncHandle,
    PipelinedEvaluator,
    StreamPool,
    evaluate_async,
    get_async_executor,
    reset_async_executor,
)
from pysymex.accel.bytecode import CompiledConstraint
from pysymex.accel.bytecode import compile_constraint
from pysymex.accel.dispatcher import evaluate_bag


class _DummyStream:
    def __init__(self) -> None:
        self.sync_calls = 0

    def synchronize(self) -> None:
        self.sync_calls += 1


def _compiled_constraint(name: str) -> CompiledConstraint:
    var = z3.Bool(name)
    return compile_constraint(var, [name])


def _bitmap_with_first_byte(v: int) -> npt.NDArray[np.uint8]:
    base = evaluate_bag(compile_constraint(z3.BoolVal(True), ["k0", "k1", "k2", "k3", "k4"])).bitmap.copy()
    base[0] = v
    return base


def _bitmap_four_bytes(a: int, b: int, c: int, d: int) -> npt.NDArray[np.uint8]:
    base = evaluate_bag(compile_constraint(z3.BoolVal(True), ["u0", "u1", "u2", "u3", "u4"])).bitmap.copy()
    base[0] = a
    base[1] = b
    base[2] = c
    base[3] = d
    return base


class TestAsyncHandle:
    def test_wait_and_done(self) -> None:
        fut: Future[npt.NDArray[np.uint8]] = Future()
        fut.set_result(_bitmap_with_first_byte(7))
        handle = AsyncHandle(future=fut, stream_id=2, constraint_hash=11)

        result = handle.wait()
        assert handle.done() is True
        assert int(result[0]) == 7

    def test_cancel(self) -> None:
        fut: Future[npt.NDArray[np.uint8]] = Future()
        handle = AsyncHandle(future=fut, stream_id=0, constraint_hash=3)

        assert handle.cancel() is True
        assert handle.done() is True


class TestStreamPool:
    def test_get_stream_round_robin(self) -> None:
        pool = StreamPool(num_streams=2)
        s0 = _DummyStream()
        s1 = _DummyStream()

        def _init_once() -> None:
            streams: list[object] = [s0, s1]
            object.__setattr__(pool, "_streams", streams)
            object.__setattr__(pool, "_initialized", True)

        with patch.object(pool, "_ensure_initialized", _init_once):
            stream_a, id_a = pool.get_stream()
            stream_b, id_b = pool.get_stream()
            stream_c, id_c = pool.get_stream()

        assert stream_a is s0
        assert id_a == 0
        assert stream_b is s1
        assert id_b == 1
        assert stream_c is s0
        assert id_c == 0

    def test_synchronize_all_safe_when_uninitialized(self) -> None:
        pool = StreamPool(num_streams=2)
        pool.synchronize_all()

    def test_synchronize_all_calls_each_stream(self) -> None:
        pool = StreamPool(num_streams=2)
        s0 = _DummyStream()
        s1 = _DummyStream()

        streams: list[object] = [s0, s1]
        object.__setattr__(pool, "_streams", streams)
        object.__setattr__(pool, "_initialized", True)

        pool.synchronize_all()

        assert s0.sync_calls == 1
        assert s1.sync_calls == 1

    def test_num_streams(self) -> None:
        pool = StreamPool(num_streams=5)
        assert pool.num_streams == 5


class TestAsyncGPUExecutor:
    def test_submit_returns_bitmap_and_tracks_stream(self) -> None:
        executor = AsyncGPUExecutor(num_streams=2, max_workers=1)
        out_stream = _DummyStream()

        def fake_get_stream() -> tuple[object, int]:
            return _DummyStream(), 1

        class _DummyOutput:
            def get(self) -> npt.NDArray[np.uint8]:
                return _bitmap_four_bytes(1, 0, 1, 0)

        def fake_evaluate_bag_async(
            _constraint: CompiledConstraint, _stream: object
        ) -> tuple[_DummyOutput, _DummyStream]:
            return _DummyOutput(), out_stream

        def fake_get_stream_method(_self: StreamPool) -> tuple[object, int]:
            return fake_get_stream()

        with patch.object(StreamPool, "get_stream", fake_get_stream_method):
            with patch("pysymex.accel.backends.gpu.evaluate_bag_async", fake_evaluate_bag_async):
                constraint = _compiled_constraint("c_submit")
                handle = executor.submit(constraint)
                result = handle.wait(timeout=2.0)

        assert handle.stream_id == 1
        assert handle.constraint_hash == constraint.source_hash
        assert list(result) == [1, 0, 1, 0]
        assert out_stream.sync_calls == 1

        executor.shutdown()

    def test_submit_batch(self) -> None:
        executor = AsyncGPUExecutor(num_streams=1, max_workers=1)

        def fake_submit(constraint: CompiledConstraint) -> AsyncHandle:
            fut: Future[npt.NDArray[np.uint8]] = Future()
            value = 4 if constraint.source_hash == constraints[0].source_hash else 5
            fut.set_result(_bitmap_with_first_byte(value))
            return AsyncHandle(
                future=fut,
                stream_id=0,
                constraint_hash=int(constraint.source_hash),
            )

        constraints = [_compiled_constraint("batch_a"), _compiled_constraint("batch_b")]

        with patch.object(executor, "submit", fake_submit):
            handles = executor.submit_batch(constraints)
        assert [h.constraint_hash for h in handles] == [c.source_hash for c in constraints]

        executor.shutdown()

    def test_wait_all(self) -> None:
        executor = AsyncGPUExecutor(num_streams=1, max_workers=1)

        f0: Future[npt.NDArray[np.uint8]] = Future()
        f1: Future[npt.NDArray[np.uint8]] = Future()
        f0.set_result(_bitmap_with_first_byte(9))
        f1.set_result(_bitmap_with_first_byte(8))
        handles = [
            AsyncHandle(future=f0, stream_id=0, constraint_hash=9),
            AsyncHandle(future=f1, stream_id=0, constraint_hash=8),
        ]

        results = executor.wait_all(handles)
        assert [int(r[0]) for r in results] == [9, 8]

        executor.shutdown()

    def test_shutdown_synchronizes_stream_pool(self) -> None:
        executor = AsyncGPUExecutor(num_streams=1, max_workers=1)
        synced = {"called": False}

        def fake_sync() -> None:
            synced["called"] = True

        def fake_sync_method(_self: StreamPool) -> None:
            fake_sync()

        with patch.object(StreamPool, "synchronize_all", fake_sync_method):
            executor.shutdown(wait=True)

        assert synced["called"] is True


class TestPipelinedEvaluator:
    def test_evaluate_sequence_preserves_order(self) -> None:
        class _FakeExecutor:
            instances: list["_FakeExecutor"] = []

            def __init__(self, num_streams: int = 4) -> None:
                self.num_streams = num_streams
                self.values: dict[int, int] = {}
                _FakeExecutor.instances.append(self)

            def submit(self, constraint: CompiledConstraint) -> AsyncHandle:
                fut: Future[npt.NDArray[np.uint8]] = Future()
                value = self.values.get(constraint.source_hash, 0)
                fut.set_result(_bitmap_with_first_byte(value))
                return AsyncHandle(
                    future=fut,
                    stream_id=0,
                    constraint_hash=int(constraint.source_hash),
                )

            def submit_batch(self, constraints: list[CompiledConstraint]) -> list[AsyncHandle]:
                return [self.submit(c) for c in constraints]

            def wait_all(
                self, handles: list[AsyncHandle], timeout: float | None = None
            ) -> list[npt.NDArray[np.uint8]]:
                return [h.wait(timeout) for h in handles]

            def shutdown(self, wait: bool = True) -> None:
                return None

        with patch("pysymex.accel.async_exec.AsyncGPUExecutor", _FakeExecutor):
            evaluator = PipelinedEvaluator(num_streams=2, prefetch=1)

            constraints = [
                _compiled_constraint("seq_a"),
                _compiled_constraint("seq_b"),
                _compiled_constraint("seq_c"),
            ]
            fake_exec = _FakeExecutor.instances[0]
            fake_exec.values = {
                constraints[0].source_hash: 1,
                constraints[1].source_hash: 2,
                constraints[2].source_hash: 3,
            }
            outputs = list(evaluator.evaluate_sequence(iter(constraints)))

        assert [int(x[0]) for x in outputs] == [1, 2, 3]
        evaluator.shutdown()

    def test_evaluate_batch(self) -> None:
        class _FakeExecutor:
            instances: list["_FakeExecutor"] = []

            def __init__(self, num_streams: int = 4) -> None:
                self.num_streams = num_streams
                self.values: dict[int, int] = {}
                _FakeExecutor.instances.append(self)

            def submit(self, constraint: CompiledConstraint) -> AsyncHandle:
                fut: Future[npt.NDArray[np.uint8]] = Future()
                value = self.values.get(constraint.source_hash, 0)
                fut.set_result(_bitmap_with_first_byte(value))
                return AsyncHandle(
                    future=fut,
                    stream_id=0,
                    constraint_hash=int(constraint.source_hash),
                )

            def submit_batch(self, constraints: list[CompiledConstraint]) -> list[AsyncHandle]:
                return [self.submit(c) for c in constraints]

            def wait_all(
                self, handles: list[AsyncHandle], timeout: float | None = None
            ) -> list[npt.NDArray[np.uint8]]:
                return [h.wait(timeout) for h in handles]

            def shutdown(self, wait: bool = True) -> None:
                return None

        with patch("pysymex.accel.async_exec.AsyncGPUExecutor", _FakeExecutor):
            evaluator = PipelinedEvaluator(num_streams=3, prefetch=2)
            constraints = [_compiled_constraint("batch_x"), _compiled_constraint("batch_y")]
            fake_exec = _FakeExecutor.instances[0]
            fake_exec.values = {
                constraints[0].source_hash: 10,
                constraints[1].source_hash: 11,
            }

            outputs = evaluator.evaluate_batch(constraints)
        assert [int(x[0]) for x in outputs] == [10, 11]
        evaluator.shutdown()

    def test_shutdown(self) -> None:
        calls = {"count": 0}

        class _FakeExecutor:
            def __init__(self, num_streams: int = 4) -> None:
                self.num_streams = num_streams

            def shutdown(self, wait: bool = True) -> None:
                calls["count"] += 1

        with patch("pysymex.accel.async_exec.AsyncGPUExecutor", _FakeExecutor):
            evaluator = PipelinedEvaluator(num_streams=1, prefetch=1)
        evaluator.shutdown()
        assert calls["count"] == 1


def test_get_async_executor_singleton_behavior() -> None:
    reset_async_executor()
    ex0 = get_async_executor()
    ex1 = get_async_executor()

    assert ex0 is ex1


def test_evaluate_async_delegates_to_global_executor() -> None:
    fut: Future[npt.NDArray[np.uint8]] = Future()
    fut.set_result(_bitmap_with_first_byte(6))
    constraint = _compiled_constraint("global_async")
    expected = AsyncHandle(future=fut, stream_id=3, constraint_hash=constraint.source_hash)

    class _FakeGlobal:
        def submit(self, constraint: CompiledConstraint) -> AsyncHandle:
            assert constraint.source_hash == expected.constraint_hash
            return expected

    with patch("pysymex.accel.async_exec.get_async_executor", lambda: _FakeGlobal()):
        handle = evaluate_async(constraint)

    assert handle is expected
    assert int(handle.wait()[0]) == 6


def test_reset_async_executor_shuts_down_and_recreates() -> None:
    reset_async_executor()
    ex0 = get_async_executor()
    reset_async_executor()
    ex1 = get_async_executor()

    assert ex0 is not ex1
