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

"""asyncio queue model."""

from __future__ import annotations

from collections import deque
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Generic, TypeVar, cast

T = TypeVar("T")


@dataclass
class QueueModel(Generic[T]):
    """Model for asyncio.Queue - a FIFO queue for async tasks."""

    maxsize: int = 0
    _queue: deque[T] = field(default_factory=lambda: cast("deque[T]", deque()))
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
        return self._queue.popleft()

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
        return self._queue.popleft()

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


__all__ = ["QueueModel"]
