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

"""Graceful shutdown helpers for async pysymex operations.

The module provides three small primitives:

* :func:`cancel_all_tasks` cancels every pending task on an event loop except
  the current task when one exists.
* :func:`install_signal_handlers` installs SIGINT and SIGTERM handlers that
  schedule task cancellation on the target loop.
* :func:`run_with_shutdown` wraps ``asyncio.run()`` and converts cancellation
  caused by an installed shutdown signal into ``KeyboardInterrupt``.

On Unix-like platforms, handlers are installed through
``loop.add_signal_handler``.  When event-loop signal handlers are unavailable
or unsupported, process-level ``signal.signal`` handlers are installed where
Python allows it.  The returned :class:`ShutdownHandle` restores installed
handlers deterministically.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from types import FrameType
from typing import TypeAlias, TypeVar

from pysymex.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")
SignalHandler: TypeAlias = int | signal.Handlers | Callable[[int, FrameType | None], object] | None


def _signal_name(signum: int) -> str:
    """Return a stable signal name for diagnostics."""
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


@dataclass(slots=True)
class ShutdownHandle:
    """Installed signal-handler state that can be restored deterministically."""

    loop: asyncio.AbstractEventLoop
    _loop_signals: tuple[signal.Signals, ...] = ()
    _previous_handlers: tuple[tuple[signal.Signals, SignalHandler], ...] = ()
    _shutdown_requested: bool = False
    _closed: bool = False

    @property
    def shutdown_requested(self) -> bool:
        """Return whether a registered shutdown signal has been observed."""
        return self._shutdown_requested

    def request_shutdown(self, sig_name: str) -> None:
        """Schedule cancellation of tasks owned by this handle's event loop."""
        self._shutdown_requested = True
        logger.info("Received %s - initiating graceful shutdown", sig_name)
        if self.loop.is_closed():
            return
        try:
            self.loop.call_soon_threadsafe(cancel_all_tasks, self.loop)
        except RuntimeError:
            logger.debug("Event loop rejected graceful shutdown scheduling", exc_info=True)

    def record_installation(
        self,
        loop_signals: list[signal.Signals],
        previous_handlers: list[tuple[signal.Signals, SignalHandler]],
    ) -> None:
        """Record installed handlers after registration succeeds."""
        self._loop_signals = tuple(loop_signals)
        self._previous_handlers = tuple(previous_handlers)

    def close(self) -> None:
        """Restore installed signal handlers once the protected run has finished."""
        if self._closed:
            return
        self._closed = True

        for sig in self._loop_signals:
            try:
                self.loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError, ValueError):
                logger.debug("Failed to remove loop signal handler for %s", sig.name, exc_info=True)

        for sig, previous_handler in self._previous_handlers:
            if previous_handler is None:
                continue
            try:
                signal.signal(sig, previous_handler)
            except (OSError, RuntimeError, TypeError, ValueError):
                logger.debug(
                    "Failed to restore process signal handler for %s",
                    sig.name,
                    exc_info=True,
                )


def cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> int:
    """Cancel every pending task on *loop* except the current one.

    This mirrors the cleanup logic in ``asyncio.run()`` but can be called from
    a signal handler callback.  The return value is the number of tasks that
    were asked to cancel.
    """
    if loop.is_closed():
        return 0

    try:
        to_cancel = asyncio.all_tasks(loop)
    except RuntimeError:
        return 0

    try:
        current = asyncio.current_task(loop=loop)
    except RuntimeError:
        current = None
    if current is not None:
        to_cancel.discard(current)

    if not to_cancel:
        return 0

    logger.info("Cancelling %d outstanding task(s)", len(to_cancel))
    for task in to_cancel:
        task.cancel()
    return len(to_cancel)


def _install_process_signal_handler(
    handle: ShutdownHandle,
    sig: signal.Signals,
    previous_handlers: list[tuple[signal.Signals, SignalHandler]],
) -> None:
    """Install a process-level handler when the loop cannot own *sig*."""

    def _process_handler(signum: int, frame: FrameType | None) -> None:
        """Request cooperative shutdown for a process-level signal."""
        _ = frame
        handle.request_shutdown(_signal_name(signum))

    try:
        previous = signal.getsignal(sig)
        signal.signal(sig, _process_handler)
    except (OSError, RuntimeError, ValueError):
        logger.debug("Process signal handler unavailable for %s", sig.name, exc_info=True)
        return

    previous_handlers.append((sig, previous))


def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> ShutdownHandle:
    """Install SIGINT / SIGTERM handlers that cancel running tasks.

    On Unix-like platforms the handlers are registered via
    ``loop.add_signal_handler``.  Otherwise, process-level ``signal.signal``
    handlers are installed where Python allows it.  The returned handle can be
    closed to restore process and loop handlers.
    """
    handle = ShutdownHandle(loop=loop)
    loop_signals: list[signal.Signals] = []
    previous_handlers: list[tuple[signal.Signals, SignalHandler]] = []
    handled_signals = (signal.SIGINT, signal.SIGTERM)

    if sys.platform == "win32":
        for sig in handled_signals:
            _install_process_signal_handler(handle, sig, previous_handlers)
    else:
        for sig in handled_signals:
            try:
                loop.add_signal_handler(sig, handle.request_shutdown, sig.name)
            except (NotImplementedError, RuntimeError, ValueError):
                logger.debug(
                    "Loop signal handler unavailable for %s; trying process handler",
                    sig.name,
                    exc_info=True,
                )
                _install_process_signal_handler(handle, sig, previous_handlers)
            else:
                loop_signals.append(sig)

    handle.record_installation(loop_signals, previous_handlers)
    return handle


def run_with_shutdown(coro: Coroutine[object, object, T]) -> T:
    """Run *coro* with signal-based graceful shutdown.

    Args:
        coro: The top-level coroutine to run.

    Returns:
        The return value of *coro*.

    Raises:
        KeyboardInterrupt: Raised when a registered shutdown signal cancels
            the top-level coroutine.
        asyncio.CancelledError: Preserved when the coroutine cancels itself
            without a registered shutdown signal.
    """

    async def _main() -> T:
        """Run the coroutine while translating registered cancellation."""
        loop = asyncio.get_running_loop()
        handle = install_signal_handlers(loop)
        try:
            return await coro
        except asyncio.CancelledError as exc:
            if handle.shutdown_requested:
                raise KeyboardInterrupt from exc
            raise
        finally:
            handle.close()

    return asyncio.run(_main())


__all__ = [
    "ShutdownHandle",
    "cancel_all_tasks",
    "install_signal_handlers",
    "run_with_shutdown",
]
