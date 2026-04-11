import pytest
import pysymex.core.shutdown
import asyncio
import signal

@pytest.mark.asyncio
async def test_cancel_all_tasks() -> None:
    """Scenario: pending tasks exist; expected all non-current tasks are cancelled."""

    async def wait_forever() -> None:
        await asyncio.sleep(10)

    task = asyncio.create_task(wait_forever())
    await asyncio.sleep(0)
    pysymex.core.shutdown.cancel_all_tasks(asyncio.get_running_loop())
    await asyncio.sleep(0)
    assert task.cancelled() is True


def test_install_signal_handlers() -> None:
    """Scenario: Windows path installation; expected SIGINT handler registration."""
    loop = asyncio.new_event_loop()
    registered: list[int] = []

    def fake_signal(sig: int, handler: object) -> None:
        registered.append(sig)

    original_platform = pysymex.core.shutdown.sys.platform
    original_signal = signal.signal
    try:
        pysymex.core.shutdown.sys.platform = "win32"
        signal.signal = fake_signal
        pysymex.core.shutdown.install_signal_handlers(loop)
    finally:
        signal.signal = original_signal
        pysymex.core.shutdown.sys.platform = original_platform
        loop.close()
    assert registered == [signal.SIGINT]


def test_run_with_shutdown() -> None:
    """Scenario: run coroutine through helper; expected coroutine return value."""

    async def coro() -> int:
        return 99

    assert pysymex.core.shutdown.run_with_shutdown(coro()) == 99
