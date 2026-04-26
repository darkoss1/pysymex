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

"""Dispatcher Memory Management Utilities.

Provides memory budget calculations, device memory monitoring,
and utilities for efficient Dispatcher utilization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import numpy as np
import numpy.typing as npt

if TYPE_CHECKING:
    from pysymex.accel.bytecode import CompiledConstraint

__all__ = [
    "DispatcherMemoryError",
    "MemoryBudget",
    "calculate_memory_budget",
    "estimate_max_treewidth",
]


class DispatcherMemoryError(Exception):
    """Raised when memory requirements exceed available resources."""

    pass


@dataclass(frozen=True, slots=True)
class MemoryBudget:
    """Memory requirements for constraint evaluation.

    Attributes:
        output_bytes: Size of output bitmap (2^w / 8)
        instruction_bytes: Size of instruction arrays
        register_bytes_per_thread: Per-thread register usage (informational,
            for occupancy analysis; NOT included in total_device_bytes since
            registers are allocated from SM register files, not global memory)
        total_device_bytes: Total global device memory required
        total_threads: Number of threads (2^w)
        recommended_batch_size: Recommended batch size if too large
    """

    output_bytes: int
    instruction_bytes: int
    register_bytes_per_thread: int
    total_device_bytes: int
    total_threads: int
    recommended_batch_size: int | None = None

    @property
    def output_mb(self) -> float:
        return self.output_bytes / (1024 * 1024)

    @property
    def total_mb(self) -> float:
        return self.total_device_bytes / (1024 * 1024)

    def fits_in_memory(self, available_mb: int) -> bool:
        return self.total_mb <= available_mb

    def __repr__(self) -> str:
        return (
            f"MemoryBudget(output={self.output_mb:.2f}MB, "
            f"total={self.total_mb:.2f}MB, threads={self.total_threads:,})"
        )


@runtime_checkable
class _MemoryInfoProvider(Protocol):
    """Protocol for SAT backend modules that expose memory telemetry."""

    def get_memory_info(self) -> dict[str, bool | int]:
        """Return backend-specific device memory information."""
        ...


def calculate_memory_budget(
    num_variables: int,
    num_instructions: int,
) -> MemoryBudget:
    """Calculate SAT memory requirements for constraint evaluation.

    Computes the total device memory needed for evaluating a compiled
    constraint with the given number of variables and instructions.

    Args:
        num_variables: Number of Boolean variables (determines 2^w states)
        num_instructions: Number of bytecode instructions

    Returns:
        MemoryBudget with size breakdown and batch recommendations
    """
    num_states = 1 << num_variables
    output_bytes = (num_states + 7) // 8
    instruction_bytes = num_instructions * 16
    register_bytes_per_thread = 32

    total_device_bytes = output_bytes + instruction_bytes + 4096

    recommended_batch = None
    if num_states > 2**26:
        recommended_batch = 2**24

    return MemoryBudget(
        output_bytes=output_bytes,
        instruction_bytes=instruction_bytes,
        register_bytes_per_thread=register_bytes_per_thread,
        total_device_bytes=total_device_bytes,
        total_threads=num_states,
        recommended_batch_size=recommended_batch,
    )


def estimate_max_treewidth(available_memory_mb: int) -> int:
    """Estimate maximum treewidth that fits in available memory.

    Conservatively estimates the largest bag width w that can be evaluated
    given available device memory, accounting for 90% utilization headroom.

    Note: While bytecode.MAX_VARIABLES allows up to 40 variables, this
    function caps at 30 for practical memory constraints (2^30 = 1 billion
    states = 128MB output bitmap). For w > 30, consider batched evaluation.

    Args:
        available_memory_mb: Available device memory in megabytes

    Returns:
        Maximum treewidth (capped at 30 for memory safety)
    """
    import math

    available_bytes = available_memory_mb * 1024 * 1024
    usable_bytes = int(available_bytes * 0.9)
    max_w = int(math.log2(usable_bytes * 8))

    return min(max_w, 30)


def get_device_memory_info() -> dict[str, bool | int]:
    """Query Device memory information.

    Attempts to retrieve SAT device memory statistics if available.

    Returns:
        Dictionary with memory info (free, total bytes) or {"available": False}
    """
    try:
        from pysymex.accel.backends import sat

        if sat.is_available() and isinstance(sat, _MemoryInfoProvider):
            return sat.get_memory_info()
    except ImportError:
        return {"available": False}

    return {"available": False}


def evaluate_batched(
    constraint: CompiledConstraint,
    batch_size: int = 2**20,
) -> npt.NDArray[np.uint8]:
    """Evaluate a constraint and return the satisfying assignment bitmap.

    Note: True batched evaluation (splitting large constraints into memory-
    efficient chunks) is planned for a future release. Currently this function
    performs a single full evaluation via the Tiered dispatcher.

    The batch_size parameter is retained for API stability but is currently
    unused. When batching is implemented, constraints with w > 26 will be
    split into smaller batches and partial results combined with bitwise OR.

    Args:
        constraint: Compiled constraint to evaluate
        batch_size: Reserved for future batched evaluation (currently unused)

    Returns:
        Bitmap of all satisfying assignments
    """
    from pysymex.accel.dispatcher import get_dispatcher

    return get_dispatcher().evaluate_bag(constraint).bitmap
