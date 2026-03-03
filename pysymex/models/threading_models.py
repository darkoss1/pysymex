"""Symbolic models for Python's threading module.

Provides symbolic representations of threading primitives that track
lock state, thread lifecycle, and synchronization for integration with
pysymex's concurrency analysis pipeline.
"""

from __future__ import annotations


import itertools

from typing import Any

_thread_id_counter = itertools.count()

_lock_id_counter = itertools.count()


class ThreadModel:
    """Symbolic model of threading.Thread."""

    def __init__(
        self,
        target: Any = None,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        name: str | None = None,
        daemon: bool = False,
    ) -> None:
        self._thread_id = f"thread_{next(_thread_id_counter)}"

        self._started = False

        self._alive = False

        self._target = target

        self._args: tuple[Any, ...] = args

        self._kwargs = kwargs or {}

        self.name = name or self._thread_id

        self.daemon = daemon

    @property
    def thread_id(self) -> str:
        return self._thread_id

    def start(self) -> None:
        """Mark thread as started and alive."""

        if self._started:
            raise RuntimeError("threads can only be started once")

        self._started = True

        self._alive = True

    def join(self, timeout: float | None = None) -> None:
        """Mark thread as joined (no longer alive)."""

        self._alive = False

    def is_alive(self) -> bool:
        """Check if thread is currently running."""

        return self._alive

    def __repr__(self) -> str:
        status = "started" if self._started else "not started"

        alive = "alive" if self._alive else "dead"

        return f"ThreadModel({self.name}, {status}, {alive})"


class LockModel:
    """Symbolic model of threading.Lock."""

    def __init__(self) -> None:
        self._name = f"lock_{next(_lock_id_counter)}"

        self._locked = False

        self._owner: str | None = None

    @property
    def name(self) -> str:
        return self._name

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire the lock."""

        if self._locked and not blocking:
            return False

        self._locked = True

        return True

    def release(self) -> None:
        """Release the lock."""

        if not self._locked:
            raise RuntimeError("release unlocked lock")

        self._locked = False

        self._owner = None

    def locked(self) -> bool:
        """Check if the lock is held."""

        return self._locked

    def __enter__(self) -> LockModel:
        self.acquire()

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    def __repr__(self) -> str:
        status = "locked" if self._locked else "unlocked"

        return f"LockModel({self._name}, {status})"


class RLockModel(LockModel):
    """Symbolic model of threading.RLock (reentrant lock)."""

    def __init__(self) -> None:
        super().__init__()

        self._count = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire the reentrant lock.

        Same owner can acquire multiple times; count is incremented.
        """

        if self._locked and self._owner is not None:
            self._count += 1

            return True

        if self._locked and not blocking:
            return False

        self._locked = True

        self._count = 1

        return True

    def release(self) -> None:
        """Release one level of reentrant lock."""

        if not self._locked or self._count <= 0:
            raise RuntimeError("release unlocked lock")

        self._count -= 1

        if self._count == 0:
            self._locked = False

            self._owner = None

    def __repr__(self) -> str:
        status = f"locked(count={self._count})" if self._locked else "unlocked"

        return f"RLockModel({self._name}, {status})"


class SemaphoreModel:
    """Symbolic model of threading.Semaphore."""

    def __init__(self, value: int = 1) -> None:
        if value < 0:
            raise ValueError("semaphore initial value must be >= 0")

        self._value = value

        self._initial_value = value

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        """Acquire (decrement) the semaphore."""

        if self._value <= 0 and not blocking:
            return False

        if self._value > 0:
            self._value -= 1

            return True

        return False

    def release(self, n: int = 1) -> None:
        """Release (increment) the semaphore."""

        self._value += n

    def __enter__(self) -> SemaphoreModel:
        self.acquire()

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    def __repr__(self) -> str:
        return f"SemaphoreModel(value={self._value})"


class BoundedSemaphoreModel(SemaphoreModel):
    """Symbolic model of threading.BoundedSemaphore."""

    def release(self, n: int = 1) -> None:
        """Release with bounds check."""

        if self._value + n > self._initial_value:
            raise ValueError("Semaphore released too many times")

        self._value += n


class EventModel:
    """Symbolic model of threading.Event."""

    def __init__(self) -> None:
        self._flag = False

        self._waiters: list[str] = []

    def is_set(self) -> bool:
        """Check if the event flag is set."""

        return self._flag

    def set(self) -> None:
        """Set the event flag, waking all waiters."""

        self._flag = True

        self._waiters.clear()

    def clear(self) -> None:
        """Clear the event flag."""

        self._flag = False

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the event flag to be set."""

        return self._flag

    def __repr__(self) -> str:
        return f"EventModel(set={self._flag})"


class ConditionModel:
    """Symbolic model of threading.Condition."""

    def __init__(self, lock: LockModel | None = None) -> None:
        self._lock = lock or LockModel()

        self._waiters: list[str] = []

    def acquire(self, *args: Any) -> bool:
        """Acquire the underlying lock."""

        return self._lock.acquire()

    def release(self) -> None:
        """Release the underlying lock."""

        self._lock.release()

    def locked(self) -> bool:
        """Check if the underlying lock is held."""

        return self._lock.locked()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for notification."""

        self._lock.release()

        self._lock.acquire()

        return True

    def wait_for(
        self,
        predicate: Any,
        timeout: float | None = None,
    ) -> bool:
        """Wait until predicate returns True."""

        return True

    def notify(self, n: int = 1) -> None:
        """Notify n waiting threads."""

        for _ in range(min(n, len(self._waiters))):
            if self._waiters:
                self._waiters.pop(0)

    def notify_all(self) -> None:
        """Notify all waiting threads."""

        self._waiters.clear()

    def __enter__(self) -> ConditionModel:
        self.acquire()

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    def __repr__(self) -> str:
        return f"ConditionModel(locked={self._lock.locked()})"


class BarrierModel:
    """Symbolic model of threading.Barrier."""

    def __init__(
        self,
        parties: int,
        action: Any = None,
        timeout: float | None = None,
    ) -> None:
        if parties < 1:
            raise ValueError("parties must be >= 1")

        self._parties = parties

        self._count = 0

        self._action = action

        self._broken = False

        self._default_timeout = timeout

    def wait(self, timeout: float | None = None) -> int:
        """Wait at the barrier. Returns arrival index."""

        if self._broken:
            raise RuntimeError("barrier is broken")

        arrival_index = self._count

        self._count += 1

        if self._count >= self._parties:
            if self._action is not None:
                try:
                    self._action()

                except Exception:
                    self._broken = True

                    raise

            self._count = 0

        return arrival_index

    def reset(self) -> None:
        """Reset the barrier."""

        self._count = 0

        self._broken = False

    def abort(self) -> None:
        """Place the barrier into a broken state."""

        self._broken = True

    @property
    def parties(self) -> int:
        """Number of parties required to trip the barrier."""

        return self._parties

    @property
    def n_waiting(self) -> int:
        """Number of threads currently waiting."""

        return self._count

    @property
    def broken(self) -> bool:
        """Check if the barrier is in a broken state."""

        return self._broken

    def __repr__(self) -> str:
        return (
            f"BarrierModel(parties={self._parties}, "
            f"waiting={self._count}, broken={self._broken})"
        )


THREADING_MODELS: dict[str, Any] = {
    "Thread": ThreadModel,
    "Lock": LockModel,
    "RLock": RLockModel,
    "Semaphore": SemaphoreModel,
    "BoundedSemaphore": BoundedSemaphoreModel,
    "Event": EventModel,
    "Condition": ConditionModel,
    "Barrier": BarrierModel,
}


def get_threading_model(name: str) -> Any | None:
    """Look up a threading model by name.

    Args:
        name: Name of the threading primitive (e.g., "Lock", "Thread").

    Returns:
        Model class or None if not found.
    """

    return THREADING_MODELS.get(name)
