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

    def send(self, value: Any) -> T:
        """Send a value into the coroutine."""

        if self._done:
            raise StopIteration(self._result)

        return self._result

    def throw(
        self, typ: type[BaseException], val: BaseException | None = None, _tb: Any = None
    ) -> T:
        """Throw an exception into the coroutine."""

        if val is None:
            val = typ()

        self._exception = val

        raise val

    def close(self) -> None:
        """Close the coroutine."""

        self._done = True

    def __await__(self) -> Any:
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

    _owner: Any = None

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

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> None:
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

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> None:
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

    async def __aexit__(self, exc_type: type | None, exc_val: Any, exc_tb: Any) -> None:
        """Exit the condition as async context manager."""

        self.release()


@dataclass
class QueueModel(Generic[T]):
    """Model for asyncio.Queue - a FIFO queue for async tasks."""

    maxsize: int = 0

    _queue: list[Any] = field(default_factory=list[Any])

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

    def __await__(self) -> Any:
        """Make the Future awaitable."""

        return iter([None, self.result()])


ASYNCIO_MODELS: dict[str, Any] = {
    "Task": TaskModel,
    "Event": EventModel,
    "Lock": LockModel,
    "Semaphore": SemaphoreModel,
    "Condition": ConditionModel,
    "Queue": QueueModel,
    "PriorityQueue": QueueModel,
    "LifoQueue": QueueModel,
    "Future": FutureModel,
    "sleep": lambda _delay: type("sleep_coro", (), {"__await__": lambda self: (yield None)})(),
    "gather": lambda *coros: [None] * len(coros),
    "wait": lambda coros: ({"done": set(), "pending": set(coros)}, None),
    "wait_for": lambda coro, timeout: coro,
    "create_task": lambda coro: TaskModel(coro),
    "run": lambda coro, loop=None: None,
    "new_event_loop": lambda: type(
        "Loop",
        (),
        {
            "run_until_complete": lambda self, coro: None,
            "close": lambda self: None,
        },
    )(),
    "get_event_loop": lambda: type(
        "Loop",
        (),
        {
            "run_until_complete": lambda self, coro: None,
            "close": lambda self: None,
        },
    )(),
    "get_running_loop": lambda: type("Loop", (), {})(),
    "shield": lambda coro: coro,
    "timeout": lambda _delay: type(
        "timeout_ctx",
        (),
        {
            "__aenter__": lambda self: None,
            "__aexit__": lambda self, *args: None,
        },
    )(),
    "to_thread": lambda func, *args: func(*args),
    "from_thread": lambda func, *args: func(*args),
}


def get_asyncio_model(name: str) -> Any | None:
    """Get an asyncio model by name."""

    return ASYNCIO_MODELS.get(name)


__all__ = [
    "CoroutineModel",
    "TaskModel",
    "EventModel",
    "LockModel",
    "SemaphoreModel",
    "ConditionModel",
    "QueueModel",
    "FutureModel",
    "ASYNCIO_MODELS",
    "get_asyncio_model",
]
