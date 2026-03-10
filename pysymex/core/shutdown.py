"""Graceful shutdown helpers for async pysymex operations.

Provides:

* :func:`install_signal_handlers` – installs SIGINT / SIGTERM handlers
  that cancel all running tasks within the current event loop.
* :func:`cancel_all_tasks` – utility to cancel every non-current task.
* :func:`run_with_shutdown` – convenience wrapper around ``asyncio.run()``
  that installs signal handlers and ensures clean teardown.

The signal handlers work by cancelling running ``asyncio.Task`` objects,
which causes ``asyncio.CancelledError`` to propagate through any active
``TaskGroup``.  The TaskGroup then cancels all sibling tasks and exits,
giving a clean structured-concurrency shutdown.

On Windows, only SIGINT (Ctrl+C) is usable with ``loop.add_signal_handler``
via a fallback to ``signal.signal``.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Coroutine
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


def cancel_all_tasks(loop: asyncio.AbstractEventLoop) -> None:
    """Cancel every pending task on *loop* except the current one.

    This mirrors the cleanup logic in ``asyncio.run()`` but can be
    called from a signal handler callback.
    """
    to_cancel = asyncio.all_tasks(loop)
    current = asyncio.current_task()
    if current is not None:
        to_cancel.discard(current)

    if not to_cancel:
        return

    logger.info("Cancelling %d outstanding task(s)…", len(to_cancel))
    for task in to_cancel:
        task.cancel()


def install_signal_handlers(loop: asyncio.AbstractEventLoop) -> None:
    """Install SIGINT / SIGTERM handlers that cancel running tasks.

    On Unix the handlers are registered via ``loop.add_signal_handler``.
    On Windows, where ``add_signal_handler`` only supports SIGINT in
    limited fashion, we fall back to ``signal.signal`` for SIGINT.
    SIGTERM on Windows is not typically delivered to console apps so
    we install it best-effort.
    """

    def _shutdown(sig_name: str) -> None:
        logger.info("Received %s – initiating graceful shutdown", sig_name)
        cancel_all_tasks(loop)

    if sys.platform == "win32":

        _original_sigint = signal.getsignal(signal.SIGINT)

        def _win_handler(signum: int, frame: object) -> None:
            _shutdown(signal.Signals(signum).name)

            signal.signal(signal.SIGINT, _original_sigint)

        signal.signal(signal.SIGINT, _win_handler)
    else:

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _shutdown, sig.name)


def run_with_shutdown(coro: Coroutine[Any, Any, T]) -> T:
    """Run *coro* with signal-based graceful shutdown.

    This is a thin wrapper around ``asyncio.run()`` that:

    1. Creates a new event loop.
    2. Installs signal handlers (SIGINT / SIGTERM).
    3. Runs the coroutine.
    4. On cancellation, ensures remaining tasks are cleaned up.

    Args:
        coro: The top-level coroutine to run.

    Returns:
        The return value of *coro*.

    Raises:
        KeyboardInterrupt: Re-raised if the coroutine was cancelled
            by a SIGINT signal.
    """

    async def _main() -> T:
        loop = asyncio.get_running_loop()
        install_signal_handlers(loop)
        return await coro

    return asyncio.run(_main())


__all__ = [
    "cancel_all_tasks",
    "install_signal_handlers",
    "run_with_shutdown",
]
