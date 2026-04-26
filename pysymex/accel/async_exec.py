# pysymex: Python Symbolic Execution & Formal Verification
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

"""Asynchronous SAT Execution with ThreadPoolExecutor.

Provides concurrent evaluation of multiple constraints using a thread pool.
Each thread uses a dedicated SAT stream, but synchronizes immediately after
kernel launch (no true pipelining).

Concurrency model:
- Multiple ThreadPoolExecutor threads can submit work to different SAT streams
- Each submission blocks within its thread until SAT kernel completes
- Overall throughput improves when evaluating multiple bags concurrently

Note: True SAT stream pipelining (overlapping transfers and kernels without
synchronization) is planned for a future release.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np
import numpy.typing as npt

from pysymex.accel.backends import BackendError

if TYPE_CHECKING:
    from pysymex.accel.bytecode import CompiledConstraint

__all__ = [
    "AsyncSatExecutor",
    "AsyncHandle",
    "PipelinedEvaluator",
    "StreamPool",
]


@dataclass
class AsyncHandle:
    """Handle for asynchronous SAT evaluation.

    Use wait() to block until completion and retrieve results.

    Attributes:
        future: Underlying Future object
        stream_id: SAT stream used
        constraint_hash: Hash of evaluated constraint
    """

    future: Future[npt.NDArray[np.uint8]]
    stream_id: int
    constraint_hash: int

    def wait(self, timeout: float | None = None) -> npt.NDArray[np.uint8]:
        """Block until evaluation completes and return result.

        Args:
            timeout: Maximum seconds to wait (None for unlimited)

        Returns:
            Bitmap of satisfying assignments

        Raises:
            TimeoutError: If timeout expires
        """
        return self.future.result(timeout=timeout)

    def done(self) -> bool:
        """Check if evaluation has completed.

        Returns:
            True if completed
        """
        return self.future.done()

    def cancel(self) -> bool:
        """Attempt to cancel pending evaluation.

        Returns:
            True if cancellation successful
        """
        return self.future.cancel()


class StreamPool:
    """Pool of SAT streams for concurrent kernel execution.

    Manages a fixed pool of SAT streams, allocating them in round-robin
    fashion to enable pipeline parallelism.

    Attributes:
        num_streams: Number of streams in the pool
    """

    def __init__(self, num_streams: int = 4) -> None:
        """Initialize stream pool.

        Args:
            num_streams: Number of SAT streams to create
        """
        self._num_streams = num_streams
        self._streams: list[int] = []
        self._current_idx = 0
        self._lock = threading.Lock()
        self._initialized = False

    def _ensure_initialized(self) -> None:
        """Lazy initialization of SAT streams.

        Raises:
            BackendError: If SAT is not available
        """
        if self._initialized:
            return

        try:
            from pysymex.accel.backends import sat

            if not sat.is_available():
                raise BackendError("SAT not available")

            self._streams = list(range(self._num_streams))
            self._initialized = True
        except ImportError:
            raise BackendError("Numba not installed (pip install numba)") from None

    def get_stream(self) -> tuple[int, int]:
        """Get next available stream from pool.

        Returns:
            Tuple of (stream_token, stream_id)
        """
        self._ensure_initialized()

        with self._lock:
            stream = self._streams[self._current_idx]
            stream_id = self._current_idx
            self._current_idx = (self._current_idx + 1) % self._num_streams
            return stream, stream_id

    def synchronize_all(self) -> None:
        """Block until all streams complete pending work."""
        if not self._initialized:
            return

    @property
    def num_streams(self) -> int:
        return self._num_streams


class AsyncSatExecutor:
    """Asynchronous executor for SAT constraint evaluation.

    Submits constraints to multiple SAT streams in parallel,
    enabling concurrent data transfers and kernel execution.

    Attributes:
        num_streams: Number of SAT streams in pool
    """

    def __init__(self, num_streams: int = 4, max_workers: int = 4) -> None:
        """Initialize async executor.

        Args:
            num_streams: Number of SAT streams
            max_workers: Thread pool size for async operations
        """
        self._stream_pool = StreamPool(num_streams)
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._pending: dict[int, AsyncHandle] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def submit(self, constraint: CompiledConstraint) -> AsyncHandle:
        """Submit constraint for asynchronous evaluation.

        Args:
            constraint: Compiled constraint to evaluate

        Returns:
            AsyncHandle for result retrieval
        """
        _stream_token, stream_id = self._stream_pool.get_stream()

        def evaluate_on_stream() -> npt.NDArray[np.uint8]:
            from pysymex.accel.backends import sat as sat_backend

            result = sat_backend.evaluate_bag(constraint)
            return result.view(np.uint8)

        future = self._executor.submit(evaluate_on_stream)

        handle = AsyncHandle(
            future=future,
            stream_id=stream_id,
            constraint_hash=constraint.source_hash,
        )

        return handle

    def submit_batch(
        self,
        constraints: list[CompiledConstraint],
    ) -> list[AsyncHandle]:
        """Submit multiple constraints for concurrent evaluation.

        Args:
            constraints: List of constraints to evaluate

        Returns:
            List of AsyncHandles for each constraint
        """
        return [self.submit(c) for c in constraints]

    def wait_all(
        self, handles: list[AsyncHandle], timeout: float | None = None
    ) -> list[npt.NDArray[np.uint8]]:
        """Wait for all handles to complete.

        Args:
            handles: List of AsyncHandles
            timeout: Maximum seconds to wait per handle

        Returns:
            List of result bitmaps
        """
        return [h.wait(timeout) for h in handles]

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown executor and synchronize streams.

        Args:
            wait: Block until all pending tasks complete
        """
        self._executor.shutdown(wait=wait)
        self._stream_pool.synchronize_all()


class PipelinedEvaluator:
    """Pipelined evaluator for sequential constraint batches.

    Overlaps evaluation of multiple constraints by maintaining
    a window of in-flight operations across SAT streams.

    Attributes:
        prefetch: Number of constraints to keep in-flight
    """

    def __init__(
        self,
        num_streams: int = 4,
        prefetch: int = 2,
    ) -> None:
        """Initialize pipelined evaluator.

        Args:
            num_streams: Number of SAT streams for parallelism
            prefetch: Pipeline depth (constraints in-flight)
        """
        self._executor = AsyncSatExecutor(num_streams=num_streams)
        self._prefetch = prefetch

    def evaluate_sequence(
        self,
        constraints: Iterator[CompiledConstraint],
    ) -> Iterator[npt.NDArray[np.uint8]]:
        """Evaluate constraint sequence with pipelined execution.

        Args:
            constraints: Iterator of compiled constraints

        Yields:
            Bitmaps in same order as input constraints
        """
        pending: list[AsyncHandle] = []

        for constraint in constraints:
            handle = self._executor.submit(constraint)
            pending.append(handle)

            while len(pending) > self._prefetch:
                result = pending.pop(0).wait()
                yield result

        for handle in pending:
            yield handle.wait()

    def evaluate_batch(
        self,
        constraints: list[CompiledConstraint],
    ) -> list[npt.NDArray[np.uint8]]:
        """Evaluate constraint list with pipelined execution.

        Args:
            constraints: List of compiled constraints

        Returns:
            List of bitmaps in same order as input
        """
        handles = self._executor.submit_batch(constraints)
        return self._executor.wait_all(handles)

    def shutdown(self) -> None:
        """Shutdown executor and cleanup resources."""
        self._executor.shutdown()


_global_executor: AsyncSatExecutor | None = None


def get_async_executor() -> AsyncSatExecutor:
    """Get or create global async executor instance.

    Returns:
        Singleton AsyncSatExecutor
    """
    global _global_executor
    if _global_executor is None:
        _global_executor = AsyncSatExecutor()
    return _global_executor


def evaluate_async(constraint: CompiledConstraint) -> AsyncHandle:
    """Submit constraint for async evaluation using global executor.

    Args:
        constraint: Compiled constraint

    Returns:
        AsyncHandle for result retrieval
    """
    return get_async_executor().submit(constraint)


def reset_async_executor() -> None:
    """Shutdown and reset global async executor.

    Used primarily for testing and cleanup.
    """
    global _global_executor
    if _global_executor is not None:
        _global_executor.shutdown()
        _global_executor = None
