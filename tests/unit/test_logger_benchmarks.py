from __future__ import annotations

import logging
import time
from io import StringIO
from collections.abc import Callable

import pytest

from pysymex._internal.logging.levels import LogLevel
from pysymex._internal.logging.logger import PysymexLogger


def _elapsed(call_count: int, action: Callable[[], None]) -> float:
    start = time.perf_counter()
    for _ in range(call_count):
        action()
    return time.perf_counter() - start


@pytest.mark.bench
def test_disabled_debug_trace_microbenchmark_reports_local_timing() -> None:
    """Report disabled pysymex vs stdlib logging timings without a brittle CI gate."""
    calls = 100_000
    pysymex_logger = PysymexLogger(level=LogLevel.NORMAL, stream=StringIO(), color=False)
    stdlib_logger = logging.getLogger("pysymex.benchmark.disabled")
    stdlib_logger.handlers.clear()
    stdlib_logger.addHandler(logging.NullHandler())
    stdlib_logger.propagate = False
    stdlib_logger.setLevel(logging.INFO)

    trace_seconds = _elapsed(calls, lambda: pysymex_logger.trace("trace message"))
    debug_seconds = _elapsed(calls, lambda: pysymex_logger.debug("debug message"))
    stdlib_seconds = _elapsed(calls, lambda: stdlib_logger.debug("debug message"))

    print(
        "logger microbenchmark: "
        f"calls={calls} pysymex_trace={trace_seconds:.6f}s "
        f"pysymex_debug={debug_seconds:.6f}s stdlib_debug={stdlib_seconds:.6f}s"
    )
    assert pysymex_logger.get_entries() == []


@pytest.mark.bench
def test_enabled_and_history_microbenchmark_reports_local_timing() -> None:
    """Report enabled lightweight and bounded-history timings."""
    calls = 5_000
    stream = StringIO()
    enabled_logger = PysymexLogger(level=LogLevel.DEBUG, stream=stream, color=False)
    history_logger = PysymexLogger(
        level=LogLevel.DEBUG,
        stream=StringIO(),
        color=False,
        history_capacity=64,
    )

    enabled_seconds = _elapsed(calls, lambda: enabled_logger.info("enabled %d", 1))
    metadata_seconds = _elapsed(
        calls,
        lambda: enabled_logger.debug("structured", metadata={"path_id": 1, "solver": "sat"}),
    )
    history_seconds = _elapsed(calls, lambda: history_logger.debug("history"))

    print(
        "logger enabled microbenchmark: "
        f"calls={calls} enabled={enabled_seconds:.6f}s "
        f"metadata={metadata_seconds:.6f}s history={history_seconds:.6f}s"
    )
    assert len(history_logger.get_entries()) == 64


@pytest.mark.bench
def test_disabled_exception_microbenchmark_reports_local_timing() -> None:
    """Disabled exception logging should not format or retain tracebacks."""
    calls = 100_000
    logger = PysymexLogger(level=LogLevel.NORMAL, stream=StringIO(), color=False)
    seconds = _elapsed(calls, lambda: logger.debug("debug", exc_info=True))

    print(f"logger exception microbenchmark: calls={calls} disabled_exc_info={seconds:.6f}s")
    assert logger.get_entries() == []
