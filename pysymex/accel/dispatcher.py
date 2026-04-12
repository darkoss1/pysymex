# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""GPU Backend Dispatcher.

Automatic backend selection and constraint evaluation dispatching.
Selects the best available backend (CUDA > CPU > Reference)
and provides a unified interface for constraint evaluation.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

import numpy as np
import numpy.typing as npt

from pysymex.accel.backends import BackendError, BackendInfo, BackendType
from pysymex.accel.memory import estimate_max_treewidth

if TYPE_CHECKING:
    from pysymex.accel.bytecode import CompiledConstraint

__all__ = [
    "BackendType",
    "DispatchResult",
    "GPUDispatcher",
    "count_satisfying",
    "evaluate_bag",
    "get_backend_info",
    "get_dispatcher",
    "iter_satisfying",
    "warmup",
]

logger = logging.getLogger(__name__)


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


def _mask_unused_tail_bits(
    bitmap: npt.NDArray[np.uint8],
    num_states: int,
) -> npt.NDArray[np.uint8]:
    """Zero padding bits beyond the semantic assignment space."""
    if bitmap.size == 0:
        return bitmap
    remainder = num_states & 7
    if remainder == 0:
        return bitmap
    masked = bitmap.copy()
    masked[-1] &= np.uint8((1 << remainder) - 1)
    return masked


class Backend(Protocol):
    """Protocol for backend modules."""

    def evaluate_bag(self, constraint: CompiledConstraint) -> npt.NDArray[np.uint8]: ...
    def get_info(self) -> BackendInfo: ...
    def warmup(self) -> None: ...


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Result from constraint evaluation.

    Attributes:
        bitmap: Packed bitmap of satisfying assignments
        backend_used: Which backend was used
        kernel_time_ms: Kernel execution time in milliseconds
        total_time_ms: Total time including transfers
    """

    bitmap: npt.NDArray[np.uint8]
    backend_used: BackendType
    kernel_time_ms: float
    total_time_ms: float
    transfer_time_ms: float = 0.0
    routing_cost_ms: float = 0.0
    _num_satisfying: int = field(default=-1, repr=False)

    def count_satisfying(self) -> int:
        """Count satisfying assignments (cached)."""
        if self._num_satisfying < 0:
            object.__setattr__(self, "_num_satisfying", int(_unpackbits_little(self.bitmap).sum()))
        return self._num_satisfying

    def __repr__(self) -> str:
        return f"DispatchResult(backend={self.backend_used.name}, time={self.total_time_ms:.3f}ms)"


class GPUDispatcher:
    """GPU backend dispatcher with automatic selection.

    Probes available backends on initialization and selects the best one
    according to priority: CUDA > CPU > Reference.

    Attributes:
        BACKEND_PRIORITY: Preference order for backend selection
    """

    BACKEND_PRIORITY: list[BackendType] = [
        BackendType.GPU,
        BackendType.CPU,
        BackendType.REFERENCE,
    ]

    def __init__(self, force_backend: BackendType | None = None) -> None:
        """Initialize dispatcher.

        Args:
            force_backend: Force use of specific backend (for testing)

        Raises:
            ValueError: If forced backend is not available
            BackendError: If no backends are available
        """
        self._backends: dict[BackendType, Backend] = {}
        self._backend_info: dict[BackendType, BackendInfo] = {}
        self._selected_backend: BackendType | None = None
        self._forced_backend = force_backend
        self._backend_latency_ewma_ms: dict[BackendType, float] = {}
        self._routing_decisions: dict[BackendType, int] = {
            BackendType.GPU: 0,
            BackendType.CPU: 0,
            BackendType.REFERENCE: 0,
        }
        self._guardrail_fallbacks: int = 0
        self._ewma_alpha: float = 0.35
        self._default_memory_bandwidth_mb_per_s: float = 12000.0

        self._probe_backends()

        if force_backend is not None:
            if force_backend not in self._backends:
                avail = [bt.name for bt in self._backends]
                raise ValueError(f"Backend {force_backend.name} not available. Available: {avail}")
            self._selected_backend = force_backend
        else:
            self._select_best_backend()

        logger.info(
            f"GPU dispatcher initialized: {self._selected_backend.name if self._selected_backend else 'None'}"
        )

    def _probe_backends(self) -> None:
        """Probe all backends to determine availability."""
        try:
            from pysymex.accel.backends import gpu

            info = gpu.get_info()
            self._backend_info[BackendType.GPU] = info
            if info.available:
                self._backends[BackendType.GPU] = gpu
                logger.debug(f"CUDA backend available: {info.name}")
        except ImportError:
            self._backend_info[BackendType.GPU] = BackendInfo(
                backend_type=BackendType.GPU,
                name="CuPy NVRTC",
                available=False,
                max_treewidth=0,
                error_message="cupy not installed",
            )

        try:
            from pysymex.accel.backends import cpu

            info = cpu.get_info()
            self._backend_info[BackendType.CPU] = info
            if info.available:
                self._backends[BackendType.CPU] = cpu
                logger.debug(f"CPU backend available: {info.name}")
        except ImportError:
            self._backend_info[BackendType.CPU] = BackendInfo(
                backend_type=BackendType.CPU,
                name="Numba CPU",
                available=False,
                max_treewidth=0,
                error_message="numba not installed",
            )

        try:
            from pysymex.accel.backends import reference

            info = reference.get_info()
            self._backend_info[BackendType.REFERENCE] = info
            if info.available:
                self._backends[BackendType.REFERENCE] = reference
                logger.debug(f"Reference backend available: {info.name}")
        except ImportError:
            pass

    def _select_best_backend(self) -> None:
        """Select best available backend by priority."""
        for backend_type in self.BACKEND_PRIORITY:
            if backend_type in self._backends:
                self._selected_backend = backend_type
                return

        raise BackendError("No GPU backends available. Install numba.")

    @property
    def selected_backend(self) -> BackendType:
        """Get currently selected backend type."""
        if self._selected_backend is None:
            raise RuntimeError("No backend selected")
        return self._selected_backend

    def get_backend_info(self) -> BackendInfo:
        """Get information about selected backend."""
        if self._selected_backend is None:
            raise RuntimeError("No backend selected")
        return self._backend_info[self._selected_backend]

    def list_backends(self) -> list[BackendInfo]:
        """List all probed backends (available and unavailable)."""
        return list(self._backend_info.values())

    def backend_items(self) -> list[tuple[BackendType, Backend]]:
        """Expose probed backend instances for orchestration helpers."""
        return list(self._backends.items())

    def evaluate_bag(self, constraint: CompiledConstraint) -> DispatchResult:
        """Evaluate constraint using selected backend.

        Args:
            constraint: Compiled constraint

        Returns:
            DispatchResult with bitmap and timing

        Raises:
            RuntimeError: If no backend selected
            BackendError: If evaluation fails
        """
        if self._selected_backend is None:
            raise RuntimeError("No backend selected")

        backend_type = self._select_backend_for_constraint(constraint)
        backend = self._backends[backend_type]

        routing_start = time.perf_counter()
        routing_cost_ms = self._estimate_backend_cost_ms(backend_type, constraint)
        transfer_time_ms = self._estimate_transfer_time_ms(backend_type, constraint)
        routing_elapsed_ms = (time.perf_counter() - routing_start) * 1000.0

        t_start = time.perf_counter()
        bitmap = backend.evaluate_bag(constraint)
        bitmap = _mask_unused_tail_bits(bitmap, 1 << constraint.num_variables)
        t_end = time.perf_counter()

        elapsed_ms = (t_end - t_start) * 1000
        self._record_backend_latency(backend_type, elapsed_ms)
        self._routing_decisions[backend_type] += 1

        return DispatchResult(
            bitmap=bitmap,
            backend_used=backend_type,
            kernel_time_ms=elapsed_ms,
            total_time_ms=elapsed_ms,
            transfer_time_ms=transfer_time_ms,
            routing_cost_ms=routing_cost_ms + routing_elapsed_ms,
        )

    def _select_backend_for_constraint(self, constraint: CompiledConstraint) -> BackendType:
        if self._forced_backend is not None:
            return self._forced_backend

        candidates: list[BackendType] = []
        for backend_type in self.BACKEND_PRIORITY:
            backend = self._backends.get(backend_type)
            info = self._backend_info.get(backend_type)
            if backend is None or info is None:
                continue
            if constraint.num_variables > info.max_treewidth:
                continue
            if backend_type == BackendType.GPU and self._should_guardrail_gpu(constraint):
                self._guardrail_fallbacks += 1
                continue
            candidates.append(backend_type)

        if not candidates:
            return self.selected_backend

        best = candidates[0]
        best_cost = self._estimate_backend_cost_ms(best, constraint)
        for backend_type in candidates[1:]:
            cost = self._estimate_backend_cost_ms(backend_type, constraint)
            if cost < best_cost:
                best = backend_type
                best_cost = cost
        return best

    def _should_guardrail_gpu(self, constraint: CompiledConstraint) -> bool:
        info = self._backend_info.get(BackendType.GPU)
        if info is None or info.device_memory_mb <= 0:
            return False
        memory_limited_max_w = estimate_max_treewidth(info.device_memory_mb)
        return constraint.num_variables > memory_limited_max_w

    def _estimate_transfer_time_ms(
        self, backend_type: BackendType, constraint: CompiledConstraint
    ) -> float:
        if backend_type != BackendType.GPU:
            return 0.0
        bytes_to_transfer = constraint.memory_bytes()
        mb_to_transfer = float(bytes_to_transfer) / (1024.0 * 1024.0)
        return (mb_to_transfer / self._default_memory_bandwidth_mb_per_s) * 1000.0

    def _estimate_backend_cost_ms(
        self, backend_type: BackendType, constraint: CompiledConstraint
    ) -> float:
        info = self._backend_info.get(backend_type)
        if info is None:
            return float("inf")

        ops = float(constraint.num_states * max(1, constraint.instruction_count))
        throughput = max(0.001, info.throughput_estimate or 0.001)
        baseline_ms = (ops / (throughput * 1_000_000_000.0)) * 1000.0
        transfer_ms = self._estimate_transfer_time_ms(backend_type, constraint)
        historical = self._backend_latency_ewma_ms.get(backend_type)
        if historical is None:
            return baseline_ms + transfer_ms
        return (0.4 * (baseline_ms + transfer_ms)) + (0.6 * historical)

    def _record_backend_latency(self, backend_type: BackendType, elapsed_ms: float) -> None:
        previous = self._backend_latency_ewma_ms.get(backend_type)
        if previous is None:
            self._backend_latency_ewma_ms[backend_type] = elapsed_ms
            return
        alpha = self._ewma_alpha
        self._backend_latency_ewma_ms[backend_type] = (alpha * elapsed_ms) + (
            (1.0 - alpha) * previous
        )

    def get_routing_stats(self) -> dict[str, object]:
        return {
            "selected_backend": self.selected_backend.name,
            "forced_backend": self._forced_backend.name if self._forced_backend else None,
            "routing_decisions": {k.name: v for k, v in self._routing_decisions.items()},
            "latency_ewma_ms": {k.name: v for k, v in self._backend_latency_ewma_ms.items()},
            "guardrail_fallbacks": self._guardrail_fallbacks,
        }

    def evaluate_bag_with_fallback(
        self,
        constraint: CompiledConstraint,
    ) -> DispatchResult:
        """Evaluate constraint with automatic fallback to other backends.

        Attempts all backends in priority order until one succeeds.

        Args:
            constraint: Compiled constraint

        Returns:
            DispatchResult from first successful backend

        Raises:
            BackendError: If all backends fail
        """
        errors: list[tuple[BackendType, Exception]] = []

        for backend_type in self.BACKEND_PRIORITY:
            if backend_type not in self._backends:
                continue

            backend = self._backends[backend_type]
            try:
                t_start = time.perf_counter()
                bitmap = backend.evaluate_bag(constraint)
                t_end = time.perf_counter()

                elapsed_ms = (t_end - t_start) * 1000

                if backend_type != self._selected_backend:
                    logger.warning(
                        f"Fell back from {self._selected_backend.name if self._selected_backend else 'None'} "
                        f"to {backend_type.name}"
                    )

                return DispatchResult(
                    bitmap=bitmap,
                    backend_used=backend_type,
                    kernel_time_ms=elapsed_ms,
                    total_time_ms=elapsed_ms,
                )
            except Exception as e:
                errors.append((backend_type, e))
                continue

        error_msg = "; ".join(f"{bt.name}: {e}" for bt, e in errors)
        raise BackendError(f"All backends failed: {error_msg}")


_dispatcher: GPUDispatcher | None = None


def get_dispatcher(force_backend: BackendType | None = None) -> GPUDispatcher:
    """Get or create global dispatcher instance.

    Args:
        force_backend: Optional backend to force (for testing)

    Returns:
        Singleton dispatcher instance
    """
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = GPUDispatcher(force_backend)
    return _dispatcher


def evaluate_bag(constraint: CompiledConstraint) -> DispatchResult:
    """Evaluate constraint using global dispatcher.

    Convenience wrapper around get_dispatcher().evaluate_bag().

    Args:
        constraint: Compiled constraint

    Returns:
        DispatchResult with bitmap and timing
    """
    return get_dispatcher().evaluate_bag(constraint)


def get_backend_info() -> BackendInfo:
    """Get information about currently selected backend.

    Returns:
        BackendInfo for selected backend
    """
    return get_dispatcher().get_backend_info()


def count_satisfying(bitmap: npt.NDArray[np.uint8]) -> int:
    """Count satisfying assignments in bitmap.

    Args:
        bitmap: Packed bitmap from evaluate_bag

    Returns:
        Number of set bits
    """
    return int(_unpackbits_little(bitmap).sum())


def iter_satisfying(
    bitmap: npt.NDArray[np.uint8],
    num_vars: int,
    variable_names: list[str] | None = None,
) -> Iterator[dict[str | int, bool]]:
    """Iterate over all satisfying assignments.

    Args:
        bitmap: Packed bitmap from evaluate_bag
        num_vars: Number of variables
        variable_names: Optional variable names (uses indices if None)

    Yields:
        Assignment dicts mapping variable -> bool
    """
    bits = _unpackbits_little(bitmap)
    max_idx = 1 << num_vars

    for i, sat in enumerate(bits[:max_idx]):
        if sat:
            if variable_names:
                yield {variable_names[v]: bool((i >> v) & 1) for v in range(num_vars)}
            else:
                yield {v: bool((i >> v) & 1) for v in range(num_vars)}


def warmup() -> None:
    """Warm up all available backends.

    Triggers JIT compilation and device initialization.
    Should be called once at startup to avoid first-use latency.
    """
    dispatcher = get_dispatcher()

    for backend_type, backend in dispatcher.backend_items():
        if hasattr(backend, "warmup"):
            try:
                backend.warmup()
                logger.debug(f"Warmed up {backend_type.name}")
            except Exception as e:
                logger.warning(f"Warmup failed for {backend_type.name}: {e}")


def reset() -> None:
    """Reset global dispatcher (for testing)."""
    global _dispatcher
    _dispatcher = None

