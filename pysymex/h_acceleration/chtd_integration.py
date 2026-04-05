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

"""GPU CHTD Integration Layer.

Provides the high-level interface between CHTD's bag evaluation needs
and the GPU backend infrastructure. Handles GPU availability detection,
automatic fallback, and efficient batch evaluation.
"""

from __future__ import annotations

import logging
import types
from collections.abc import Iterator, Sequence
from typing import TYPE_CHECKING

import numpy as np
import numpy.typing as npt

if TYPE_CHECKING:
    import z3

    from pysymex.h_acceleration.backends import BackendInfo
    from pysymex.h_acceleration.dispatcher import GPUDispatcher

__all__ = [
    "GPUBagEvaluator",
    "get_bag_evaluator",
    "is_gpu_available",
]

logger = logging.getLogger(__name__)


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


_gpu_available: bool | None = None
_gpu_module: tuple[types.ModuleType, types.ModuleType] | None = None


def _init_gpu() -> bool:
    """Initialize GPU subsystem and check availability.

    Returns:
        True if GPU is available and initialized
    """
    global _gpu_available, _gpu_module

    if _gpu_available is not None:
        return _gpu_available

    try:
        from pysymex.h_acceleration import bytecode, dispatcher

        disp = dispatcher.get_dispatcher()
        info = disp.get_backend_info()

        _gpu_module = (bytecode, dispatcher)
        _gpu_available = True

        logger.info(f"GPU acceleration available: {info.name}")
        return True

    except ImportError as e:
        _gpu_available = False
        logger.info(f"GPU acceleration not available (import error): {e}")
        return False

    except Exception as e:
        _gpu_available = False
        logger.info(f"GPU acceleration not available: {e}")
        return False


def is_gpu_available() -> bool:
    """Check if GPU acceleration is available.

    Returns:
        True if GPU backends are available
    """
    return _init_gpu()


class GPUBagEvaluator:
    """High-level GPU evaluator for CHTD bag constraints.

    Provides automatic GPU/CPU selection based on problem size
    and hardware capabilities.

    Attributes:
        DEFAULT_GPU_THRESHOLD: Minimum variables for GPU use (12)
        gpu_threshold: Current threshold for this instance
        max_gpu_treewidth: Maximum supported treewidth
    """

    DEFAULT_GPU_THRESHOLD: int = 12

    def __init__(
        self,
        gpu_threshold: int = DEFAULT_GPU_THRESHOLD,
        warmup: bool = True,
    ) -> None:
        """Initialize GPU bag evaluator.

        Args:
            gpu_threshold: Minimum variables to trigger GPU use
            warmup: Whether to warmup GPU JIT compilation
        """
        self.gpu_threshold = gpu_threshold
        self._gpu_ready = _init_gpu()
        self._dispatcher: GPUDispatcher | None = None
        self._backend_info: BackendInfo | None = None
        self.max_gpu_treewidth: int = 0

        if self._gpu_ready and _gpu_module is not None:
            from pysymex.h_acceleration import dispatcher as disp_module

            self._dispatcher = disp_module.get_dispatcher()
            self._backend_info = self._dispatcher.get_backend_info()
            self.max_gpu_treewidth = self._backend_info.max_treewidth

            if warmup:
                self._warmup()

    def _warmup(self) -> None:
        """Warmup GPU JIT compilation."""
        try:
            from pysymex.h_acceleration import dispatcher

            dispatcher.warmup()
        except Exception as e:
            logger.debug(f"GPU warmup failed: {e}")

    @property
    def is_available(self) -> bool:
        """Check if GPU is ready for use."""
        return self._gpu_ready

    def get_backend_info(self) -> dict[str, bool | str | int]:
        """Get information about current backend.

        Returns:
            Dict with backend info or just available=False
        """
        if not self._gpu_ready or self._backend_info is None:
            return {"available": False}

        return {
            "available": True,
            "backend": self._backend_info.backend_type.name,
            "name": self._backend_info.name,
            "max_treewidth": self._backend_info.max_treewidth,
            "supports_async": self._backend_info.supports_async,
        }

    def should_use_gpu(self, num_variables: int) -> bool:
        """Determine if GPU should be used for given variable count.

        Args:
            num_variables: Number of Boolean variables

        Returns:
            True if GPU should be used
        """
        if not self._gpu_ready:
            return False

        if num_variables < self.gpu_threshold:
            return False

        if num_variables > self.max_gpu_treewidth:
            return False

        return True

    def evaluate_bag(
        self,
        constraints: Sequence[z3.ExprRef],
        variables: Sequence[str],
    ) -> npt.NDArray[np.uint8] | None:
        """Evaluate bag constraints using GPU.

        Args:
            constraints: Z3 constraint expressions
            variables: Variable names in order

        Returns:
            Packed bitmap of satisfying assignments, or None if GPU
            should not be used
        """
        import z3

        w = len(variables)

        if not self.should_use_gpu(w):
            return None

        if _gpu_module is None:
            return None

        from pysymex.h_acceleration import bytecode as bytecode_mod

        try:
            if not constraints:
                combined = z3.BoolVal(True)
            elif len(constraints) == 1:
                combined = constraints[0]
            else:
                combined = z3.And(*constraints)

            compiled = bytecode_mod.compile_constraint(combined, list(variables))

            if self._dispatcher is None:
                return None

            result = self._dispatcher.evaluate_bag(compiled)

            logger.debug(
                f"GPU evaluated bag w={w}: {result.count_satisfying()} SAT "
                f"in {result.kernel_time_ms:.2f}ms via {result.backend_used.name}"
            )

            return result.bitmap

        except Exception as e:
            logger.warning(f"GPU evaluation failed, falling back to CPU: {e}")
            return None

    def evaluate_bag_with_timeout(
        self,
        constraints: Sequence[z3.ExprRef],
        variables: Sequence[str],
        timeout_ms: float = 1000.0,
    ) -> npt.NDArray[np.uint8] | None:
        """Evaluate bag with estimated timeout check.

        Args:
            constraints: Z3 constraint expressions
            variables: Variable names
            timeout_ms: Maximum allowed time in milliseconds

        Returns:
            Bitmap or None if skipped/failed
        """
        w = len(variables)

        estimated_ms = self._estimate_execution_time(w, len(constraints))

        if estimated_ms > timeout_ms:
            logger.debug(
                f"Skipping GPU for w={w}: estimated {estimated_ms:.0f}ms "
                f"exceeds timeout {timeout_ms:.0f}ms"
            )
            return None

        return self.evaluate_bag(constraints, variables)

    def _estimate_execution_time(self, num_vars: int, num_constraints: int) -> float:
        """Estimate GPU execution time based on problem size.

        Args:
            num_vars: Number of variables
            num_constraints: Number of constraints

        Returns:
            Estimated milliseconds
        """
        if not self._gpu_ready or self._backend_info is None:
            return float("inf")

        num_states = 1 << num_vars

        if self._backend_info.backend_type.name == "GPU":
            a, b, c = 1e-10, 1e-7, 0.1
        else:
            a, b, c = 5e-10, 5e-7, 0.5

        return a * num_states * num_constraints + b * num_states + c

    def count_satisfying(self, bitmap: npt.NDArray[np.uint8]) -> int:
        """Count satisfying assignments in bitmap.

        Args:
            bitmap: Packed bitmap from evaluate_bag

        Returns:
            Number of set bits
        """
        return int(_unpackbits_little(bitmap).sum())

    def iter_satisfying(
        self,
        bitmap: npt.NDArray[np.uint8],
        variables: Sequence[str],
    ) -> Iterator[dict[str, bool]]:
        """Iterate over satisfying assignments.

        Args:
            bitmap: Packed bitmap from evaluate_bag
            variables: Variable names in order

        Yields:
            Assignment dicts mapping variable name -> bool
        """
        w = len(variables)
        bits = _unpackbits_little(bitmap)
        max_idx = 1 << w

        for i, sat in enumerate(bits[:max_idx]):
            if sat:
                yield {variables[v]: bool((i >> v) & 1) for v in range(w)}

    def get_satisfying_list(
        self,
        bitmap: npt.NDArray[np.uint8],
        variables: Sequence[str],
    ) -> list[dict[str, bool]]:
        """Get all satisfying assignments as list.

        Args:
            bitmap: Packed bitmap from evaluate_bag
            variables: Variable names

        Returns:
            List of assignment dicts
        """
        return list(self.iter_satisfying(bitmap, variables))


_evaluator: GPUBagEvaluator | None = None


def get_bag_evaluator(
    gpu_threshold: int = GPUBagEvaluator.DEFAULT_GPU_THRESHOLD,
) -> GPUBagEvaluator:
    """Get or create global GPU bag evaluator.

    Args:
        gpu_threshold: Minimum variables for GPU use

    Returns:
        Singleton evaluator instance
    """
    global _evaluator
    if _evaluator is None:
        _evaluator = GPUBagEvaluator(gpu_threshold=gpu_threshold)
    return _evaluator


def reset() -> None:
    """Reset global evaluator (for testing)."""
    global _evaluator
    _evaluator = None
