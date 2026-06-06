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

"""asyncio synchronization primitive models."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


@dataclass
class EventModel:
    """Model for asyncio.Event - an event that can be waited on."""

    _set: bool = False
    waiters: list[Awaitable[object]] = field(default_factory=list[Awaitable[object]])

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
    waiters: list[Awaitable[object]] = field(default_factory=list[Awaitable[object]])

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

    value: int
    _initial: int = field(init=False)
    waiters: list[Awaitable[object]] = field(default_factory=list[Awaitable[object]])

    def __post_init__(self) -> None:
        self._initial = self.value

    def locked(self) -> bool:
        """Return True if the semaphore cannot be acquired immediately."""
        return self.value == 0

    async def acquire(self) -> bool:
        """Acquire a semaphore."""
        self.value -= 1
        return True

    def release(self) -> None:
        """Release a semaphore."""
        self.value += 1

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

    lock: LockModel = field(default_factory=LockModel)
    waiters: list[Awaitable[object]] = field(default_factory=list[Awaitable[object]])

    async def acquire(self) -> bool:
        """Acquire the underlying lock."""
        return await self.lock.acquire()

    def release(self) -> None:
        """Release the underlying lock."""
        self.lock.release()

    def locked(self) -> bool:
        """Return True if the underlying lock is held."""
        return self.lock.locked()

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


__all__ = ["ConditionModel", "EventModel", "LockModel", "SemaphoreModel"]
