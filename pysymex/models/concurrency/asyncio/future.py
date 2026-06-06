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

"""asyncio Future model."""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic, TypeVar, cast

T = TypeVar("T")


class FutureModel(Generic[T]):
    """Model for asyncio.Future - a placeholder for a result that will be set later."""

    def __init__(self) -> None:
        """Initialize a new FutureModel instance."""
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
        return cast("T", self._result)

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


__all__ = ["FutureModel"]
