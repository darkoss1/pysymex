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

"""Event, condition, and barrier threading models."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING, Self

from pysymex._internal.models.stdlib.threading.state.locks import LockModel, ThreadingLockModel

if TYPE_CHECKING:
    import types


class ThreadingEventModel:
    """Symbolic model of ``threading.Event``.

    Maintains a boolean flag that threads can wait on.
    """

    def __init__(self) -> None:
        """Initialize a new EventModel instance."""
        self._flag = False
        self.waiters: deque[str] = deque()

    def is_set(self) -> bool:
        """Check if the event flag is set."""
        return self._flag

    def set(self) -> None:
        """Set the event flag, waking all waiters."""
        self._flag = True
        self.waiters.clear()

    def clear(self) -> None:
        """Clear the event flag."""
        self._flag = False

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for the event flag to be set."""
        return self._flag

    def __repr__(self) -> str:
        return f"EventModel(set={self._flag})"


class ThreadingConditionModel:
    """Symbolic model of ``threading.Condition``."""

    def __init__(self, lock: ThreadingLockModel | None = None) -> None:
        """Initialize a new ConditionModel instance."""
        self.lock = lock or LockModel()
        self.waiters: deque[str] = deque()

    def acquire(self, *args: object) -> bool:
        """Acquire the underlying lock."""
        return self.lock.acquire()

    def release(self) -> None:
        """Release the underlying lock."""
        self.lock.release()

    def locked(self) -> bool:
        """Check if the underlying lock is held."""
        return self.lock.locked()

    def wait(self, timeout: float | None = None) -> bool:
        """Wait for notification."""
        self.lock.release()
        self.lock.acquire()
        return True

    def wait_for(
        self,
        predicate: object,
        timeout: float | None = None,
    ) -> bool:
        """Wait until predicate returns True."""
        return True

    def notify(self, n: int = 1) -> None:
        """Notify n waiting threads."""
        for _ in range(min(n, len(self.waiters))):
            self.waiters.popleft()

    def notify_all(self) -> None:
        """Notify all waiting threads."""
        self.waiters.clear()

    def __enter__(self) -> Self:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.release()

    def __repr__(self) -> str:
        return f"ConditionModel(locked={self.lock.locked()})"


class BarrierModel:
    """Symbolic model of ``threading.Barrier``."""

    def __init__(
        self,
        parties: int,
        action: object = None,
        timeout: float | None = None,
    ) -> None:
        """Initialize a new BarrierModel instance."""
        if parties < 1:
            msg = "parties must be >= 1"
            raise ValueError(msg)
        self._parties = parties
        self._count = 0
        self._action = action
        self._broken = False

    def wait(self, timeout: float | None = None) -> int:
        """Wait at the barrier. Returns arrival index."""
        if self._broken:
            msg = "barrier is broken"
            raise RuntimeError(msg)
        arrival_index = self._count
        self._count += 1
        if self._count >= self._parties:
            if callable(self._action):
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
            f"BarrierModel(parties={self._parties}, waiting={self._count}, broken={self._broken})"
        )


EventModel = ThreadingEventModel
ConditionModel = ThreadingConditionModel
