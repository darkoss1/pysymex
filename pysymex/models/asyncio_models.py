"""Models for the asyncio module.

This module provides models for Python's asyncio standard library,
including coroutines, tasks, events, and synchronization primitives.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass
class CoroutineModel(Generic[T]):
    """Model for asyncio coroutines."""

    _result: T | None = None
    _exception: BaseException | None = None
    _done: bool = False

    def send(self, value: object) -> T:
        """Send a value into the coroutine."""
        if self._done:
            raise StopIteration(self._result)
        return self._result

    def throw(
        self, typ: type[BaseException], val: BaseException | None = None, _tb: object = None
    ) -> T:
        """Throw an exception into the coroutine."""
        if val is None:
            val = typ()
        self._exception = val
        raise val

    def close(self) -> None:
        """Close the coroutine."""
        self._done = True

    def __await__(self) -> object:
        """Make the model awaitable."""
        return iter([self._result])


@dataclass
class TaskModel(Generic[T]):
    """Model for asyncio.Task - a coroutine wrapped into a Future."""

    _coro: Coroutine[Any, Any, T]
    _result: T | None = None
    _exception: BaseException | None = None
    _done: bool = False
    _cancelled: bool = False
    _callbacks: list[Callable[[TaskModel[T]], None]] = field(default_factory=lambda: [])

    def result(self) -> T:
        """Return the result of the Task."""
        if self._cancelled:
            raise Exception("Task was cancelled")
        if self._exception:
            raise self._exception
        if not self._done:
            raise Exception("Task not done")
        return self._result

    def exception(self) -> BaseException | None:
        """Return the exception raised by the Task."""
        if self._cancelled:
            raise Exception("Task was cancelled")
        if not self._done:
            raise Exception("Task not done")
        return self._exception

    def done(self) -> bool:
        """Return True if the Task is done."""
        return self._done

    def cancelled(self) -> bool:
        """Return True if the Task was cancelled."""
        return self._cancelled

    def cancel(self, msg: str | None = None) -> bool:
        """Request the Task to be cancelled."""
        if self._done:
            return False
        self._cancelled = True
        self._done = True
        return True

    def add_done_callback(self, callback: Callable[[TaskModel[T]], None]) -> None:
        """Add a callback to be run when the Task is done."""
        if self._done:
            callback(self)
        else:
            self._callbacks.append(callback)

    def remove_done_callback(self, callback: Callable[[TaskModel[T]], None]) -> int:
        """Remove a callback from the done callbacks list."""
        count = self._callbacks.count(callback)
        while callback in self._callbacks:
            self._callbacks.remove(callback)
        return count

    def get_name(self) -> str:
        """Return the name of the Task."""
        return getattr(self, "_name", "Task")

    def set_name(self, value: str) -> TaskModel[T]:
        """Set the name of the Task."""
        self._name = value
        return self

    def get_coro(self) -> Coroutine[Any, Any, T]:
        """Return the coroutine wrapped by the Task."""
        return self._coro


@dataclass
class EventModel:
    """Model for asyncio.Event - an event that can be waited on."""

    _set: bool = False
    _waiters: list[Awaitable[Any]] = field(default_factory=list[Awaitable[Any]])

    def is_set(self) -> bool:
        """Return True if the event is set."""
        return self._set

    def set(self) -> None:
        """Set the event."""
        self._set = True

    def clear(self) -> None:
        """Clear the event."""
        self._set = False

    async def wait(self) -> bool:
        """Wait until the event is set."""
        return True


@dataclass
class LockModel:
    """Model for asyncio.Lock - a mutual exclusion lock."""

    _locked: bool = False
    _owner: object = None
    _waiters: list[Awaitable[Any]] = field(default_factory=list[Awaitable[Any]])

    def locked(self) -> bool:
        """Return True if the lock is acquired."""
        return self._locked

    async def acquire(self) -> bool:
        """Acquire the lock."""
        self._locked = True
        self._owner = "task"
        return True

    def release(self) -> None:
        """Release the lock."""
        if not self._locked:
            raise RuntimeError("Lock is not locked")
        self._locked = False
        self._owner = None

    async def __aenter__(self) -> LockModel:
        """Enter the lock as async context manager."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: object, exc_tb: object) -> None:
        """Exit the lock as async context manager."""
        self.release()


@dataclass
class SemaphoreModel:
    """Model for asyncio.Semaphore - a semaphore for limiting concurrent access."""

    _value: int
    _initial: int = field(init=False)
    _waiters: list[Awaitable[Any]] = field(default_factory=list[Awaitable[Any]])

    def __post_init__(self) -> None:
        self._initial = self._value

    def locked(self) -> bool:
        """Return True if the semaphore cannot be acquired immediately."""
        return self._value == 0

    async def acquire(self) -> bool:
        """Acquire a semaphore."""
        self._value -= 1
        return True

    def release(self) -> None:
        """Release a semaphore."""
        self._value += 1

    async def __aenter__(self) -> SemaphoreModel:
        """Enter the semaphore as async context manager."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: object, exc_tb: object) -> None:
        """Exit the semaphore as async context manager."""
        self.release()


@dataclass
class ConditionModel:
    """Model for asyncio.Condition - a condition variable."""

    _lock: LockModel = field(default_factory=LockModel)
    _waiters: list[Awaitable[Any]] = field(default_factory=list[Awaitable[Any]])

    async def acquire(self) -> bool:
        """Acquire the underlying lock."""
        return await self._lock.acquire()

    def release(self) -> None:
        """Release the underlying lock."""
        self._lock.release()

    def locked(self) -> bool:
        """Return True if the underlying lock is held."""
        return self._lock.locked()

    async def wait(self) -> bool:
        """Wait until notified."""
        self.release()
        await self.acquire()
        return True

    async def wait_for(self, predicate: Callable[[], bool]) -> bool:
        """Wait until a predicate becomes true."""
        while not predicate():
            await self.wait()
        return True

    def notify(self, n: int = 1) -> None:
        """Wake up at most n tasks waiting on the condition."""
        pass

    def notify_all(self) -> None:
        """Wake up all tasks waiting on the condition."""
        pass

    async def __aenter__(self) -> ConditionModel:
        """Enter the condition as async context manager."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type: type | None, exc_val: object, exc_tb: object) -> None:
        """Exit the condition as async context manager."""
        self.release()


@dataclass
class QueueModel(Generic[T]):
    """Model for asyncio.Queue - a FIFO queue for async tasks."""

    maxsize: int = 0
    _queue: list[object] = field(default_factory=list[object])
    _unfinished_tasks: int = 0

    def empty(self) -> bool:
        """Return True if the queue is empty."""
        return len(self._queue) == 0

    def full(self) -> bool:
        """Return True if the queue is full."""
        if self.maxsize <= 0:
            return False
        return len(self._queue) >= self.maxsize

    def qsize(self) -> int:
        """Return the number of items in the queue."""
        return len(self._queue)

    async def put(self, item: T) -> None:
        """Put an item into the queue."""
        self._queue.append(item)
        self._unfinished_tasks += 1

    async def get(self) -> T:
        """Remove and return an item from the queue."""
        return self._queue.pop(0)

    def put_nowait(self, item: T) -> None:
        """Put an item into the queue without blocking."""
        if self.full():
            raise Exception("Queue is full")
        self._queue.append(item)
        self._unfinished_tasks += 1

    def get_nowait(self) -> T:
        """Remove and return an item from the queue without blocking."""
        if self.empty():
            raise Exception("Queue is empty")
        return self._queue.pop(0)

    def task_done(self) -> None:
        """Indicate that a formerly enqueued task is complete."""
        if self._unfinished_tasks <= 0:
            raise ValueError("task_done() called too many times")
        self._unfinished_tasks -= 1

    def join(self) -> Awaitable[None]:
        """Block until all items in the queue have been processed."""

        async def waiter() -> None:
            pass

        return waiter()


class FutureModel(Generic[T]):
    """Model for asyncio.Future - a placeholder for a result that will be set later."""

    def __init__(self) -> None:
        self._result: T | None = None
        self._exception: BaseException | None = None
        self._done: bool = False
        self._cancelled: bool = False
        self._callbacks: list[Callable[[FutureModel[T]], None]] = []

    def result(self) -> T:
        """Return the result of the Future."""
        if self._cancelled:
            raise Exception("Future was cancelled")
        if self._exception:
            raise self._exception
        if not self._done:
            raise Exception("Future not done")
        return self._result

    def set_result(self, result: T) -> None:
        """Mark the Future as done and set its result."""
        if self._done:
            raise Exception("Future already done")
        self._result = result
        self._done = True
        for cb in self._callbacks:
            cb(self)

    def exception(self) -> BaseException | None:
        """Return the exception raised by the Future."""
        if self._cancelled:
            raise Exception("Future was cancelled")
        if not self._done:
            raise Exception("Future not done")
        return self._exception

    def set_exception(self, exception: BaseException) -> None:
        """Mark the Future as done and set an exception."""
        if self._done:
            raise Exception("Future already done")
        self._exception = exception
        self._done = True
        for cb in self._callbacks:
            cb(self)

    def done(self) -> bool:
        """Return True if the Future is done."""
        return self._done

    def cancelled(self) -> bool:
        """Return True if the Future was cancelled."""
        return self._cancelled

    def cancel(self, msg: str | None = None) -> bool:
        """Cancel the Future."""
        if self._done:
            return False
        self._cancelled = True
        self._done = True
        return True

    def add_done_callback(self, callback: Callable[[FutureModel[T]], None]) -> None:
        """Add a callback to be run when the Future is done."""
        if self._done:
            callback(self)
        else:
            self._callbacks.append(callback)

    def remove_done_callback(self, callback: Callable[[FutureModel[T]], None]) -> int:
        """Remove a callback from the done callbacks list."""
        count = self._callbacks.count(callback)
        while callback in self._callbacks:
            self._callbacks.remove(callback)
        return count

    def __await__(self) -> object:
        """Make the Future awaitable."""
        return iter([None, self.result()])


def _stub_sleep(_delay: object) -> object:
    return type("sleep_coro", (), {"__await__": lambda self: (yield None)})()


def _stub_gather(*coros: object) -> list[None]:
    return [None] * len(coros)


def _stub_wait(coros: object) -> tuple[dict[str, set[object]], None]:
    _c: set[object] = set() if not isinstance(coros, set) else coros
    return ({"done": set(), "pending": _c}, None)


def _stub_wait_for(coro: object, timeout: object) -> object:
    return coro


def _stub_create_task(coro: object) -> TaskModel:
    return TaskModel(coro)


def _stub_run(coro: object, loop: object = None) -> None:
    return None


def _make_loop() -> object:
    return type(
        "Loop", (), {"run_until_complete": lambda self, coro: None, "close": lambda self: None}
    )()


def _stub_new_event_loop() -> object:
    return _make_loop()


def _stub_get_event_loop() -> object:
    return _make_loop()


def _stub_get_running_loop() -> object:
    return type("Loop", (), {})()


def _stub_shield(coro: object) -> object:
    return coro


def _stub_timeout(_delay: object) -> object:
    return type(
        "timeout_ctx", (), {"__aenter__": lambda self: None, "__aexit__": lambda self, *args: None}
    )()


def _stub_to_thread(func: Callable[..., object], *args: object) -> object:
    return func(*args)


def _stub_from_thread(func: Callable[..., object], *args: object) -> object:
    return func(*args)


ASYNCIO_MODELS: dict[str, object] = {
    "Task": TaskModel,
    "Event": EventModel,
    "Lock": LockModel,
    "Semaphore": SemaphoreModel,
    "Condition": ConditionModel,
    "Queue": QueueModel,
    "PriorityQueue": QueueModel,
    "LifoQueue": QueueModel,
    "Future": FutureModel,
    "sleep": _stub_sleep,
    "gather": _stub_gather,
    "wait": _stub_wait,
    "wait_for": _stub_wait_for,
    "create_task": _stub_create_task,
    "run": _stub_run,
    "new_event_loop": _stub_new_event_loop,
    "get_event_loop": _stub_get_event_loop,
    "get_running_loop": _stub_get_running_loop,
    "shield": _stub_shield,
    "timeout": _stub_timeout,
    "to_thread": _stub_to_thread,
    "from_thread": _stub_from_thread,
}


def get_asyncio_model(name: str) -> object | None:
    """Get an asyncio model by name."""
    return ASYNCIO_MODELS.get(name)


__all__ = [
    "ASYNCIO_MODELS",
    "ConditionModel",
    "CoroutineModel",
    "EventModel",
    "FutureModel",
    "LockModel",
    "QueueModel",
    "SemaphoreModel",
    "TaskModel",
    "get_asyncio_model",
]
