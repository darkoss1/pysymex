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

from typing import TYPE_CHECKING, Self

from pysymex._internal.models.stdlib.threading.state.counters import lock_id_counter

if TYPE_CHECKING:
    import types

    from pysymex._internal.core.state.record import VMState


class ThreadingLockModel:
    """Symbolic model of ``threading.Lock``.

    Tracks locked/unlocked state for deadlock and race detection.
    """

    def __init__(self) -> None:
        """Initialize a new LockModel instance."""
        self._name = f"lock_{next(lock_id_counter)}"
        self._locked = False

    @staticmethod
    def apply(
        args: list[object],
        kwargs: dict[str, object],
        state: VMState,
    ) -> object:
        """Model method calls on Lock instances."""
        from pysymex._internal.core.types.scalars.values import SymbolicValue
        from pysymex._internal.models.contracts.results import ModelResult

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
            msg = "release unlocked lock"
            raise RuntimeError(msg)
        self._locked = False

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


class RLockModel(ThreadingLockModel):
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
        self._count = 1
        return True

    def release(self) -> None:
        """Release one level of reentrant lock."""
        if not self._locked or self._count <= 0:
            msg = "release unlocked lock"
            raise RuntimeError(msg)
        self._count -= 1
        if self._count == 0:
            self._locked = False

    def __repr__(self) -> str:
        status = f"locked(count={self._count})" if self._locked else "unlocked"
        return f"RLockModel({self._name}, {status})"


class ThreadingSemaphoreModel:
    """Symbolic model of ``threading.Semaphore``."""

    def __init__(self, value: int = 1) -> None:
        """Initialize a new SemaphoreModel instance."""
        if value < 0:
            msg = "semaphore initial value must be >= 0"
            raise ValueError(msg)
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


class BoundedSemaphoreModel(ThreadingSemaphoreModel):
    """Symbolic model of ``threading.BoundedSemaphore``."""

    def release(self, n: int = 1) -> None:
        """Release with bounds check."""
        if self.value + n > self._initial_value:
            msg = "Semaphore released too many times"
            raise ValueError(msg)
        self.value += n


LockModel = ThreadingLockModel
SemaphoreModel = ThreadingSemaphoreModel
