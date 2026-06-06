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

"""asyncio function stubs and registry."""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Generator
from typing import cast

from pysymex.models.concurrency.asyncio.queue import QueueModel
from pysymex.models.concurrency.asyncio.sync import (
    ConditionModel,
    EventModel,
    LockModel,
    SemaphoreModel,
)
from pysymex.models.concurrency.asyncio.future import FutureModel
from pysymex.models.concurrency.asyncio.tasks import TaskModel


class _SleepCoro:
    """Stub class for sleep coroutine."""

    def __await__(self) -> Generator[None, None, None]:
        return (yield None)


def _stub_sleep(_delay: object) -> _SleepCoro:
    """Stub sleep."""
    return _SleepCoro()


def _stub_gather(*coros: object) -> list[None]:
    """Stub gather."""
    return [None] * len(coros)


def _stub_wait(coros: object) -> tuple[dict[str, set[object]], None]:
    """Stub wait."""
    _c: set[object] = set() if not isinstance(coros, set) else cast("set[object]", coros)
    return ({"done": set(), "pending": _c}, None)


def _stub_wait_for(coro: object, timeout: object) -> object:
    """Stub wait for."""
    return coro


def _stub_create_task(coro: Coroutine[object, object, object]) -> TaskModel[object]:
    """Stub create task."""
    return TaskModel(coro)


def _stub_run(coro: object, loop: object = None) -> None:
    """Stub run."""
    return None


class _LoopStub:
    """Stub class for event loop."""

    def close(self) -> None:
        """Stub close."""


def _make_loop() -> _LoopStub:
    """Make loop."""
    return _LoopStub()


def _stub_new_event_loop() -> object:
    """Stub new event loop."""
    return _make_loop()


def _stub_get_event_loop() -> object:
    """Stub get event loop."""
    return _make_loop()


def _stub_get_running_loop() -> _LoopStub:
    """Stub get running loop."""
    return _LoopStub()


def _stub_shield(coro: object) -> object:
    """Stub shield."""
    return coro


class _TimeoutContext:
    """Stub class for timeout context manager."""

    def __aenter__(self) -> None:
        return None

    def __aexit__(self, *args: object) -> None:
        return None


def _stub_timeout(_delay: object) -> _TimeoutContext:
    """Stub timeout."""
    return _TimeoutContext()


def _stub_to_thread(func: Callable[..., object], *args: object) -> object:
    """Stub to thread."""
    return func(*args)


def _stub_from_thread(func: Callable[..., object], *args: object) -> object:
    """Stub from thread."""
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


__all__ = ["ASYNCIO_MODELS", "get_asyncio_model"]
