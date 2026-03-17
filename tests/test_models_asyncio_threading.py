"""Tests for asyncio_models.py and threading_models.py.

Phase 2 Part C -- Function Models (asyncio + threading).
"""

from __future__ import annotations

import asyncio

import pytest

from pysymex.models.asyncio_models import (
    ASYNCIO_MODELS,
    ConditionModel as AsyncConditionModel,
    CoroutineModel,
    EventModel as AsyncEventModel,
    FutureModel,
    LockModel as AsyncLockModel,
    QueueModel,
    SemaphoreModel as AsyncSemaphoreModel,
    TaskModel,
    get_asyncio_model,
    _stub_sleep,
    _stub_gather,
    _stub_wait,
    _stub_wait_for,
    _stub_create_task,
    _stub_run,
    _stub_new_event_loop,
    _stub_get_event_loop,
    _stub_get_running_loop,
    _stub_shield,
    _stub_timeout,
    _stub_to_thread,
    _stub_from_thread,
)
from pysymex.models.threading_models import (
    THREADING_MODELS,
    BarrierModel,
    BoundedSemaphoreModel,
    ConditionModel as ThreadConditionModel,
    EventModel as ThreadEventModel,
    LockModel as ThreadLockModel,
    RLockModel,
    SemaphoreModel as ThreadSemaphoreModel,
    ThreadModel,
    get_threading_model,
)


# ===================================================================
# asyncio -- CoroutineModel
# ===================================================================

class TestCoroutineModel:
    def test_initial_state(self):
        c = CoroutineModel()
        assert c._result is None
        assert c._exception is None
        assert c._done is False

    def test_send_returns_result(self):
        c = CoroutineModel(_result=42, _done=False)
        assert c.send(None) == 42

    def test_send_when_done_raises_stopiteration(self):
        c = CoroutineModel(_result=10, _done=True)
        with pytest.raises(StopIteration):
            c.send(None)

    def test_throw_raises_exception(self):
        c = CoroutineModel()
        with pytest.raises(ValueError):
            c.throw(ValueError, ValueError("boom"))
        assert c._exception is not None

    def test_close_marks_done(self):
        c = CoroutineModel()
        c.close()
        assert c._done is True

    def test_await_returns_iterator(self):
        c = CoroutineModel(_result="val")
        it = c.__await__()
        assert list(it) == ["val"]


# ===================================================================
# asyncio -- TaskModel
# ===================================================================

class TestTaskModel:
    def _make_coro(self):
        async def dummy():
            return 42
        return dummy()

    def test_initial_state(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        assert t.done() is False
        assert t.cancelled() is False
        coro.close()

    def test_cancel(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        assert t.cancel() is True
        assert t.cancelled() is True
        assert t.done() is True
        coro.close()

    def test_cancel_when_done(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _done=True, _result=1)
        assert t.cancel() is False
        coro.close()

    def test_result_when_done(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _done=True, _result=99)
        assert t.result() == 99
        coro.close()

    def test_result_when_cancelled_raises(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _cancelled=True, _done=True)
        with pytest.raises(Exception, match="cancelled"):
            t.result()
        coro.close()

    def test_result_when_not_done_raises(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        with pytest.raises(Exception, match="not done"):
            t.result()
        coro.close()

    def test_result_with_exception_raises(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _done=True, _exception=ValueError("oops"))
        with pytest.raises(ValueError, match="oops"):
            t.result()
        coro.close()

    def test_exception_when_done(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _done=True, _exception=TypeError("bad"))
        assert isinstance(t.exception(), TypeError)
        coro.close()

    def test_exception_when_not_done_raises(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        with pytest.raises(Exception, match="not done"):
            t.exception()
        coro.close()

    def test_add_done_callback_when_done(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro, _done=True, _result=1)
        called = []
        t.add_done_callback(lambda task: called.append(task))
        assert len(called) == 1
        coro.close()

    def test_add_done_callback_when_not_done(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        called = []
        t.add_done_callback(lambda task: called.append(task))
        assert len(called) == 0
        assert len(t._callbacks) == 1
        coro.close()

    def test_remove_done_callback(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        cb = lambda task: None
        t.add_done_callback(cb)
        t.add_done_callback(cb)
        removed = t.remove_done_callback(cb)
        assert removed == 2
        assert len(t._callbacks) == 0
        coro.close()

    def test_get_set_name(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        assert t.get_name() == "Task"
        t.set_name("my_task")
        assert t.get_name() == "my_task"
        coro.close()

    def test_get_coro(self):
        coro = self._make_coro()
        t = TaskModel(_coro=coro)
        assert t.get_coro() is coro
        coro.close()


# ===================================================================
# asyncio -- EventModel
# ===================================================================

class TestAsyncEventModel:
    def test_initial_not_set(self):
        e = AsyncEventModel()
        assert e.is_set() is False

    def test_set_and_clear(self):
        e = AsyncEventModel()
        e.set()
        assert e.is_set() is True
        e.clear()
        assert e.is_set() is False


# ===================================================================
# asyncio -- LockModel
# ===================================================================

class TestAsyncLockModel:
    def test_initial_unlocked(self):
        lock = AsyncLockModel()
        assert lock.locked() is False

    @pytest.mark.asyncio
    async def test_acquire_release(self):
        lock = AsyncLockModel()
        assert await lock.acquire() is True
        assert lock.locked() is True
        lock.release()
        assert lock.locked() is False

    def test_release_unlocked_raises(self):
        lock = AsyncLockModel()
        with pytest.raises(RuntimeError, match="not locked"):
            lock.release()


# ===================================================================
# asyncio -- SemaphoreModel
# ===================================================================

class TestAsyncSemaphoreModel:
    def test_initial_value(self):
        sem = AsyncSemaphoreModel(_value=3)
        assert sem.locked() is False

    @pytest.mark.asyncio
    async def test_acquire_decrements(self):
        sem = AsyncSemaphoreModel(_value=2)
        await sem.acquire()
        assert sem._value == 1
        await sem.acquire()
        assert sem._value == 0
        assert sem.locked() is True

    def test_release_increments(self):
        sem = AsyncSemaphoreModel(_value=0)
        sem.release()
        assert sem._value == 1


# ===================================================================
# asyncio -- ConditionModel
# ===================================================================

class TestAsyncConditionModel:
    @pytest.mark.asyncio
    async def test_acquire_release(self):
        cond = AsyncConditionModel()
        await cond.acquire()
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_notify_and_notify_all(self):
        cond = AsyncConditionModel()
        # Just ensure they don't raise
        cond.notify(1)
        cond.notify_all()


# ===================================================================
# asyncio -- QueueModel
# ===================================================================

class TestQueueModel:
    def test_initial_empty(self):
        q = QueueModel()
        assert q.empty() is True
        assert q.qsize() == 0

    @pytest.mark.asyncio
    async def test_put_get(self):
        q = QueueModel()
        await q.put("item1")
        assert q.qsize() == 1
        assert not q.empty()
        item = await q.get()
        assert item == "item1"

    def test_put_nowait(self):
        q = QueueModel()
        q.put_nowait("a")
        assert q.qsize() == 1

    def test_get_nowait_empty_raises(self):
        q = QueueModel()
        with pytest.raises(Exception, match="empty"):
            q.get_nowait()

    def test_full(self):
        q = QueueModel(maxsize=2)
        q.put_nowait("a")
        q.put_nowait("b")
        assert q.full() is True

    def test_put_nowait_full_raises(self):
        q = QueueModel(maxsize=1)
        q.put_nowait("a")
        with pytest.raises(Exception, match="full"):
            q.put_nowait("b")

    def test_task_done(self):
        q = QueueModel()
        q.put_nowait("a")
        q.task_done()
        assert q._unfinished_tasks == 0

    def test_task_done_too_many_raises(self):
        q = QueueModel()
        with pytest.raises(ValueError, match="too many"):
            q.task_done()

    def test_full_unbounded(self):
        q = QueueModel(maxsize=0)
        assert q.full() is False


# ===================================================================
# asyncio -- FutureModel
# ===================================================================

class TestFutureModel:
    def test_initial_state(self):
        f = FutureModel()
        assert f.done() is False
        assert f.cancelled() is False

    def test_set_result(self):
        f = FutureModel()
        f.set_result(42)
        assert f.done() is True
        assert f.result() == 42

    def test_set_result_twice_raises(self):
        f = FutureModel()
        f.set_result(1)
        with pytest.raises(Exception, match="already done"):
            f.set_result(2)

    def test_set_exception(self):
        f = FutureModel()
        f.set_exception(ValueError("bad"))
        assert f.done() is True
        assert isinstance(f.exception(), ValueError)

    def test_result_with_exception_raises(self):
        f = FutureModel()
        f.set_exception(TypeError("nope"))
        with pytest.raises(TypeError, match="nope"):
            f.result()

    def test_result_not_done_raises(self):
        f = FutureModel()
        with pytest.raises(Exception, match="not done"):
            f.result()

    def test_exception_not_done_raises(self):
        f = FutureModel()
        with pytest.raises(Exception, match="not done"):
            f.exception()

    def test_cancel(self):
        f = FutureModel()
        assert f.cancel() is True
        assert f.cancelled() is True
        assert f.done() is True

    def test_cancel_when_done(self):
        f = FutureModel()
        f.set_result(1)
        assert f.cancel() is False

    def test_result_when_cancelled_raises(self):
        f = FutureModel()
        f.cancel()
        with pytest.raises(Exception, match="cancelled"):
            f.result()

    def test_add_done_callback_before_done(self):
        f = FutureModel()
        called = []
        f.add_done_callback(lambda fut: called.append(1))
        assert len(called) == 0
        f.set_result(10)
        assert len(called) == 1

    def test_add_done_callback_after_done(self):
        f = FutureModel()
        f.set_result(10)
        called = []
        f.add_done_callback(lambda fut: called.append(1))
        assert len(called) == 1

    def test_remove_done_callback(self):
        f = FutureModel()
        cb = lambda fut: None
        f.add_done_callback(cb)
        f.add_done_callback(cb)
        removed = f.remove_done_callback(cb)
        assert removed == 2
        assert len(f._callbacks) == 0


# ===================================================================
# asyncio -- stub functions
# ===================================================================

class TestAsyncioStubs:
    def test_stub_gather(self):
        result = _stub_gather("c1", "c2", "c3")
        assert result == [None, None, None]

    def test_stub_wait(self):
        result = _stub_wait({"a", "b"})
        assert isinstance(result, tuple)

    def test_stub_wait_for(self):
        sentinel = object()
        assert _stub_wait_for(sentinel, 5) is sentinel

    def test_stub_create_task(self):
        async def coro():
            return 1
        c = coro()
        t = _stub_create_task(c)
        assert isinstance(t, TaskModel)
        c.close()

    def test_stub_run(self):
        assert _stub_run(None) is None

    def test_stub_new_event_loop(self):
        loop = _stub_new_event_loop()
        assert hasattr(loop, "run_until_complete")
        assert hasattr(loop, "close")

    def test_stub_get_event_loop(self):
        loop = _stub_get_event_loop()
        assert hasattr(loop, "run_until_complete")

    def test_stub_get_running_loop(self):
        loop = _stub_get_running_loop()
        assert loop is not None

    def test_stub_shield(self):
        sentinel = object()
        assert _stub_shield(sentinel) is sentinel

    def test_stub_to_thread(self):
        result = _stub_to_thread(lambda x: x * 2, 5)
        assert result == 10

    def test_stub_from_thread(self):
        result = _stub_from_thread(lambda x: x + 1, 3)
        assert result == 4


# ===================================================================
# asyncio -- registry
# ===================================================================

class TestAsyncioRegistry:
    def test_all_expected_models(self):
        expected = [
            "Task", "Event", "Lock", "Semaphore", "Condition",
            "Queue", "PriorityQueue", "LifoQueue", "Future",
            "sleep", "gather", "wait", "wait_for", "create_task",
            "run", "new_event_loop", "get_event_loop",
            "get_running_loop", "shield", "timeout",
            "to_thread", "from_thread",
        ]
        for name in expected:
            assert name in ASYNCIO_MODELS, f"Missing model: {name}"

    def test_get_asyncio_model(self):
        assert get_asyncio_model("Task") is TaskModel

    def test_get_unknown_returns_none(self):
        assert get_asyncio_model("nonexistent") is None

    def test_model_count(self):
        assert len(ASYNCIO_MODELS) == 22


# ===================================================================
# threading -- ThreadModel
# ===================================================================

class TestThreadModel:
    def test_initial_state(self):
        t = ThreadModel(name="worker")
        assert t.name == "worker"
        assert t.is_alive() is False
        assert t._started is False

    def test_start(self):
        t = ThreadModel()
        t.start()
        assert t.is_alive() is True
        assert t._started is True

    def test_start_twice_raises(self):
        t = ThreadModel()
        t.start()
        with pytest.raises(RuntimeError, match="only be started once"):
            t.start()

    def test_join(self):
        t = ThreadModel()
        t.start()
        t.join()
        assert t.is_alive() is False

    def test_thread_id(self):
        t = ThreadModel()
        assert t.thread_id.startswith("thread_")

    def test_daemon(self):
        t = ThreadModel(daemon=True)
        assert t.daemon is True

    def test_repr(self):
        t = ThreadModel(name="w")
        r = repr(t)
        assert "w" in r
        assert "not started" in r


# ===================================================================
# threading -- LockModel
# ===================================================================

class TestThreadLockModel:
    def test_initial_unlocked(self):
        lock = ThreadLockModel()
        assert lock.locked() is False

    def test_acquire_release(self):
        lock = ThreadLockModel()
        assert lock.acquire() is True
        assert lock.locked() is True
        lock.release()
        assert lock.locked() is False

    def test_acquire_non_blocking_fails_when_locked(self):
        lock = ThreadLockModel()
        lock.acquire()
        assert lock.acquire(blocking=False) is False

    def test_release_unlocked_raises(self):
        lock = ThreadLockModel()
        with pytest.raises(RuntimeError, match="release unlocked lock"):
            lock.release()

    def test_context_manager(self):
        lock = ThreadLockModel()
        with lock:
            assert lock.locked() is True
        assert lock.locked() is False

    def test_name(self):
        lock = ThreadLockModel()
        assert lock.name.startswith("lock_")

    def test_repr(self):
        lock = ThreadLockModel()
        assert "unlocked" in repr(lock)
        lock.acquire()
        assert "locked" in repr(lock)


# ===================================================================
# threading -- RLockModel
# ===================================================================

class TestRLockModel:
    def test_reentrant_acquire(self):
        rlock = RLockModel()
        rlock._owner = "t1"
        rlock.acquire()
        assert rlock._count == 1
        rlock.acquire()
        assert rlock._count == 2

    def test_release_decrements(self):
        rlock = RLockModel()
        rlock.acquire()
        assert rlock._count == 1
        rlock.release()
        assert rlock._count == 0
        assert rlock.locked() is False

    def test_release_unlocked_raises(self):
        rlock = RLockModel()
        with pytest.raises(RuntimeError, match="release unlocked lock"):
            rlock.release()

    def test_repr(self):
        rlock = RLockModel()
        assert "unlocked" in repr(rlock)
        rlock.acquire()
        assert "locked" in repr(rlock)


# ===================================================================
# threading -- SemaphoreModel
# ===================================================================

class TestThreadSemaphoreModel:
    def test_initial_value(self):
        sem = ThreadSemaphoreModel(3)
        assert sem._value == 3

    def test_negative_initial_raises(self):
        with pytest.raises(ValueError, match="must be >= 0"):
            ThreadSemaphoreModel(-1)

    def test_acquire_decrements(self):
        sem = ThreadSemaphoreModel(2)
        assert sem.acquire() is True
        assert sem._value == 1

    def test_acquire_at_zero_non_blocking(self):
        sem = ThreadSemaphoreModel(0)
        assert sem.acquire(blocking=False) is False

    def test_release_increments(self):
        sem = ThreadSemaphoreModel(1)
        sem.acquire()
        sem.release()
        assert sem._value == 1

    def test_context_manager(self):
        sem = ThreadSemaphoreModel(1)
        with sem:
            assert sem._value == 0
        assert sem._value == 1

    def test_repr(self):
        sem = ThreadSemaphoreModel(5)
        assert "value=5" in repr(sem)


# ===================================================================
# threading -- BoundedSemaphoreModel
# ===================================================================

class TestBoundedSemaphoreModel:
    def test_release_over_initial_raises(self):
        bsem = BoundedSemaphoreModel(1)
        with pytest.raises(ValueError, match="released too many"):
            bsem.release()

    def test_normal_acquire_release(self):
        bsem = BoundedSemaphoreModel(2)
        bsem.acquire()
        bsem.release()
        assert bsem._value == 2


# ===================================================================
# threading -- EventModel
# ===================================================================

class TestThreadEventModel:
    def test_initial_not_set(self):
        e = ThreadEventModel()
        assert e.is_set() is False

    def test_set_and_clear(self):
        e = ThreadEventModel()
        e.set()
        assert e.is_set() is True
        e.clear()
        assert e.is_set() is False

    def test_wait_returns_flag(self):
        e = ThreadEventModel()
        assert e.wait() is False
        e.set()
        assert e.wait() is True

    def test_repr(self):
        e = ThreadEventModel()
        assert "set=False" in repr(e)
        e.set()
        assert "set=True" in repr(e)


# ===================================================================
# threading -- ConditionModel
# ===================================================================

class TestThreadConditionModel:
    def test_acquire_release(self):
        cond = ThreadConditionModel()
        cond.acquire()
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_wait(self):
        cond = ThreadConditionModel()
        cond.acquire()
        # wait releases and re-acquires
        result = cond.wait()
        assert result is True
        assert cond.locked() is True

    def test_wait_for(self):
        cond = ThreadConditionModel()
        cond.acquire()
        result = cond.wait_for(lambda: True)
        assert result is True

    def test_notify(self):
        cond = ThreadConditionModel()
        cond._waiters = ["w1", "w2", "w3"]
        cond.notify(2)
        assert len(cond._waiters) == 1

    def test_notify_all(self):
        cond = ThreadConditionModel()
        cond._waiters = ["w1", "w2"]
        cond.notify_all()
        assert len(cond._waiters) == 0

    def test_context_manager(self):
        cond = ThreadConditionModel()
        with cond:
            assert cond.locked() is True
        assert cond.locked() is False

    def test_with_custom_lock(self):
        lock = ThreadLockModel()
        cond = ThreadConditionModel(lock=lock)
        cond.acquire()
        assert lock.locked() is True

    def test_repr(self):
        cond = ThreadConditionModel()
        assert "locked=False" in repr(cond)


# ===================================================================
# threading -- BarrierModel
# ===================================================================

class TestBarrierModel:
    def test_initial_state(self):
        b = BarrierModel(parties=3)
        assert b.parties == 3
        assert b.n_waiting == 0
        assert b.broken is False

    def test_invalid_parties_raises(self):
        with pytest.raises(ValueError, match="must be >= 1"):
            BarrierModel(parties=0)

    def test_wait_increments(self):
        b = BarrierModel(parties=3)
        idx = b.wait()
        assert idx == 0
        assert b.n_waiting == 1

    def test_barrier_trips_at_parties(self):
        b = BarrierModel(parties=2)
        b.wait()
        b.wait()
        # After trip, count resets
        assert b.n_waiting == 0

    def test_action_called_at_trip(self):
        called = []
        b = BarrierModel(parties=2, action=lambda: called.append(True))
        b.wait()
        b.wait()
        assert called == [True]

    def test_action_failure_breaks_barrier(self):
        def bad_action():
            raise RuntimeError("boom")
        b = BarrierModel(parties=2, action=bad_action)
        b.wait()
        with pytest.raises(RuntimeError, match="boom"):
            b.wait()
        assert b.broken is True

    def test_wait_on_broken_raises(self):
        b = BarrierModel(parties=2)
        b.abort()
        with pytest.raises(RuntimeError, match="broken"):
            b.wait()

    def test_reset(self):
        b = BarrierModel(parties=3)
        b.wait()
        b.abort()
        b.reset()
        assert b.n_waiting == 0
        assert b.broken is False

    def test_repr(self):
        b = BarrierModel(parties=3)
        r = repr(b)
        assert "parties=3" in r
        assert "waiting=0" in r
        assert "broken=False" in r


# ===================================================================
# threading -- registry
# ===================================================================

class TestThreadingRegistry:
    def test_all_expected_models(self):
        expected = [
            "Thread", "Lock", "RLock", "Semaphore",
            "BoundedSemaphore", "Event", "Condition", "Barrier",
        ]
        for name in expected:
            assert name in THREADING_MODELS, f"Missing model: {name}"

    def test_get_threading_model(self):
        assert get_threading_model("Thread") is ThreadModel
        assert get_threading_model("Lock") is ThreadLockModel

    def test_get_unknown_returns_none(self):
        assert get_threading_model("nonexistent") is None

    def test_model_count(self):
        assert len(THREADING_MODELS) == 8
