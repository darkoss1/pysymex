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

"""Lock and semaphore threading models."""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, Self

from pysymex.models.concurrency.threading.counters import lock_id_counter

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class LockModel:
    """Symbolic model of ``threading.Lock``.

    Tracks locked/unlocked state for deadlock and race detection.
    """

    def __init__(self) -> None:
        """Initialize a new LockModel instance."""
        self._name = f"lock_{next(lock_id_counter)}"
        self._locked = False
        self._owner: str | None = None

    @staticmethod
    def apply(
        args: list[object],
        kwargs: dict[str, object],
        state: "VMState",
    ) -> object:
        """Model method calls on Lock instances."""
        from pysymex.core.types.scalars.values import SymbolicValue
        from pysymex.models.builtins.base import ModelResult

        result, constraint = SymbolicValue.symbolic(f"lock_call_{state.pc}_{state.path_id}")
        return ModelResult(value=result, constraints=[constraint])

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
        status = "locked" if self._locked else "unlocked"
        return f"LockModel({self._name}, {status})"


class RLockModel(LockModel):
    """Symbolic model of ``threading.RLock`` (reentrant lock)."""

    def __init__(self) -> None:
        """Initialize a new RLockModel instance."""
        super().__init__()
        self._count = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire the reentrant lock."""
        if self._locked:
            self._count += 1
            return True

        if self._locked and not blocking:
            return False

        self._locked = True
        self._owner = "current_thread"
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
    """Symbolic model of ``threading.Semaphore``."""

    def __init__(self, value: int = 1) -> None:
        """Initialize a new SemaphoreModel instance."""
        if value < 0:
            raise ValueError("semaphore initial value must be >= 0")
        self.value = value
        self._initial_value = value

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        """Acquire (decrement) the semaphore."""
        if self.value <= 0 and not blocking:
            return False
        if self.value > 0:
            self.value -= 1
            return True

        return False

    def release(self, n: int = 1) -> None:
        """Release (increment) the semaphore."""
        self.value += n

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
        return f"SemaphoreModel(value={self.value})"


class BoundedSemaphoreModel(SemaphoreModel):
    """Symbolic model of ``threading.BoundedSemaphore``."""

    def release(self, n: int = 1) -> None:
        """Release with bounds check."""
        if self.value + n > self._initial_value:
            raise ValueError("Semaphore released too many times")
        self.value += n


__all__ = ["BoundedSemaphoreModel", "LockModel", "RLockModel", "SemaphoreModel"]
