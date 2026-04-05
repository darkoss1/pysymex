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

"""Backend Protocol and Registry.

Defines the interface all GPU backends must implement and provides
a registry for backend discovery and capability reporting.

Available Backends:
- GPU: CuPy NVRTC (high-performance CUDA via runtime compilation)
- CPU: Numba JIT (bit-sliced CPU evaluation)
- REFERENCE: Pure Python (correctness baseline)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import numpy as np
import numpy.typing as npt

if TYPE_CHECKING:
    from pysymex.h_acceleration.bytecode import CompiledConstraint

__all__ = [
    "BackendError",
    "BackendInfo",
    "BackendProtocol",
    "BackendType",
]


class BackendType(Enum):
    """Available backend types in priority order.

    Lower enum values indicate higher priority (preferred backends).
    The dispatcher will select the first available backend.
    """

    GPU = auto()
    CPU = auto()
    REFERENCE = auto()


@dataclass(frozen=True, slots=True)
class BackendInfo:
    """Information about a backend's capabilities and status.

    Attributes:
        backend_type: Type identifier for this backend
        name: Human-readable name (e.g., "CuPy NVRTC (RTX 4090)")
        available: Whether the backend can be used
        max_treewidth: Maximum supported bag treewidth
        supports_async: Whether async execution is supported
        device_memory_mb: Available device memory in MB (0 for CPU)
        compute_units: Number of compute units (SMs, cores, etc.)
        error_message: Error message if not available
    """

    backend_type: BackendType
    name: str
    available: bool
    max_treewidth: int
    supports_async: bool = False
    device_memory_mb: int = 0
    compute_units: int = 0
    error_message: str = ""

    @property
    def is_gpu(self) -> bool:
        """Check if this is a GPU backend."""
        return self.backend_type == BackendType.GPU

    @property
    def throughput_estimate(self) -> float:
        """Estimated throughput in billions of states/second.

        These are conservative baseline estimates. Actual throughput depends on:
        - Hardware (GPU model, CPU cores)
        - Constraint complexity (instruction count, register pressure)
        - Treewidth (large w benefits more from GPU parallelism)

        Modern GPUs can achieve 1000x+ higher throughput on large problems.
        """
        if self.backend_type == BackendType.GPU:
            return 100.0
        elif self.backend_type == BackendType.CPU:
            return 1.0
        else:
            return 0.001

    def __repr__(self) -> str:
        status = "available" if self.available else f"unavailable ({self.error_message})"
        return f"BackendInfo({self.name}, {status}, max_w={self.max_treewidth})"


class BackendError(Exception):
    """Error raised by backend operations.

    This exception is raised when:
    - A backend is not available
    - Constraint exceeds backend limits
    - Kernel compilation fails
    - GPU memory allocation fails
    - Device synchronization fails
    """

    pass


@runtime_checkable
class BackendProtocol(Protocol):
    """Protocol defining the interface all backends must implement.

    Backends are responsible for:
    1. Reporting availability and capabilities via get_info()
    2. Evaluating compiled constraints via evaluate_bag()
    3. Optional: count_sat() for efficient counting without bitmap
    4. Optional: warmup() for JIT precompilation
    """

    @staticmethod
    def is_available() -> bool:
        """Check if this backend is available on the current system.

        Returns:
            True if the backend can be used, False otherwise
        """
        ...

    @staticmethod
    def get_info() -> BackendInfo:
        """Get detailed information about this backend.

        Returns:
            BackendInfo with capabilities and status
        """
        ...

    @staticmethod
    def evaluate_bag(constraint: CompiledConstraint) -> npt.NDArray[np.uint8]:
        """Evaluate all 2^w Boolean assignments for a compiled constraint.

        This is the core operation: given a compiled constraint with w variables,
        evaluate all 2^w possible Boolean assignments and return a packed bitmap
        indicating which assignments satisfy the constraint.

        Args:
            constraint: Compiled constraint from bytecode compiler

        Returns:
            Packed bitmap of shape ((2^w + 7) // 8,), dtype=uint8.
            Bit i is set iff assignment with bit-pattern i satisfies the constraint.

        Raises:
            BackendError: If evaluation fails
            ValueError: If constraint exceeds backend limits
        """
        ...
