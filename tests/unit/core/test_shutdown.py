from __future__ import annotations

import asyncio
import signal
from collections.abc import Callable
from typing import cast

import pytest

import pysymex._internal.core.shutdown


class FakeSignalLoop:
    def __init__(self) -> None:
        self.closed = False
        self.added: list[tuple[signal.Signals, Callable[..., object], tuple[object, ...]]] = []
        self.removed: list[signal.Signals] = []
        self.scheduled: list[tuple[Callable[..., object], tuple[object, ...]]] = []

    def is_closed(self) -> bool:
        return self.closed

    def add_signal_handler(
        self,
        sig: signal.Signals,
        callback: Callable[..., object],
        *args: object,
    ) -> None:
        self.added.append((sig, callback, args))

    def remove_signal_handler(self, sig: signal.Signals) -> bool:
        self.removed.append(sig)
        return True

    def call_soon_threadsafe(self, callback: Callable[..., object], *args: object) -> None:
        self.scheduled.append((callback, args))


@pytest.mark.asyncio
async def test_cancel_all_tasks() -> None:
    """Scenario: pending tasks exist; expected all non-current tasks are cancelled."""

    async def wait_forever() -> None:
        await asyncio.sleep(10)

    task = asyncio.create_task(wait_forever())
    await asyncio.sleep(0)

    cancelled = pysymex._internal.core.shutdown.cancel_all_tasks(asyncio.get_running_loop())

    await asyncio.sleep(0)
    assert cancelled == 1
    assert task.cancelled() is True


def test_install_signal_handlers_uses_loop_handlers_and_restores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: loop supports signal handlers; expected handlers are removable."""
    fake_loop = FakeSignalLoop()
    loop = cast("asyncio.AbstractEventLoop", fake_loop)
    monkeypatch.setattr(pysymex._internal.core.shutdown.sys, "platform", "linux")

    handle = pysymex._internal.core.shutdown.install_signal_handlers(loop)

    assert [sig for sig, _callback, _args in fake_loop.added] == [
        signal.SIGINT,
        signal.SIGTERM,
    ]

    _sig, callback, args = fake_loop.added[0]
    callback(*args)
    assert handle.shutdown_requested is True
    assert fake_loop.scheduled == [(pysymex._internal.core.shutdown.cancel_all_tasks, (loop,))]

    handle.close()
    assert fake_loop.removed == [signal.SIGINT, signal.SIGTERM]


def test_install_signal_handlers_windows_process_handlers_restore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario: Windows path installation; expected process handlers are restored."""
    loop = asyncio.new_event_loop()
    registered: list[tuple[signal.Signals, object]] = []
    previous_handlers = {
        signal.SIGINT: signal.SIG_DFL,
        signal.SIGTERM: signal.SIG_IGN,
    }

    def fake_getsignal(sig: signal.Signals) -> object:
        return previous_handlers[sig]

    def fake_signal(sig: signal.Signals, handler: object) -> object:
        registered.append((sig, handler))
        return previous_handlers[sig]

    try:
        monkeypatch.setattr(pysymex._internal.core.shutdown.sys, "platform", "win32")
        monkeypatch.setattr(signal, "getsignal", fake_getsignal)
        monkeypatch.setattr(signal, "signal", fake_signal)

        handle = pysymex._internal.core.shutdown.install_signal_handlers(loop)
        handle.close()
    finally:
        loop.close()

    assert [sig for sig, _handler in registered[:2]] == [signal.SIGINT, signal.SIGTERM]
    assert registered[2:] == [
        (signal.SIGINT, signal.SIG_DFL),
        (signal.SIGTERM, signal.SIG_IGN),
    ]
