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

"""asyncio coroutine and task models."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Generic, TypeVar, cast

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
        return cast("T", self._result)

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

    _coro: Coroutine[object, object, T]
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
        return cast("T", self._result)

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

    def get_coro(self) -> Coroutine[object, object, T]:
        """Return the coroutine wrapped by the Task."""
        return self._coro


__all__ = ["CoroutineModel", "TaskModel"]
