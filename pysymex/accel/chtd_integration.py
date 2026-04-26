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

"""SAT CHTD Integration Layer.

Provides the high-level interface between CHTD's bag evaluation needs
and the SAT backend infrastructure. Handles SAT availability detection,
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

    from pysymex.accel.backends import BackendInfo
    from pysymex.accel.dispatcher import TieredDispatcher

__all__ = [
    "SatBagEvaluator",
    "get_bag_evaluator",
    "is_sat_available",
]

logger = logging.getLogger(__name__)


def _unpackbits_little(bitmap: npt.NDArray[np.uint8]) -> npt.NDArray[np.uint8]:
    """Return unpacked bits in little-endian bit order for each byte."""
    bits = np.unpackbits(bitmap)
    return bits.reshape(-1, 8)[:, ::-1].reshape(-1)


_sat_available: bool | None = None
_sat_module: tuple[types.ModuleType, types.ModuleType] | None = None


def _init_sat() -> bool:
    """Initialize SAT subsystem and check availability.

    Returns:
        True if SAT is available and initialized
    """
    global _sat_available, _sat_module

    if _sat_available is not None:
        return _sat_available

    try:
        from pysymex.accel import bytecode, dispatcher

        disp = dispatcher.get_dispatcher()
        info = disp.get_backend_info()

        _sat_module = (bytecode, dispatcher)
        _sat_available = True

        logger.info(f"SAT acceleration available: {info.name}")
        return True

    except ImportError as e:
        _sat_available = False
        logger.info(f"SAT acceleration not available (import error): {e}")
        return False

    except Exception as e:
        _sat_available = False
        logger.info(f"SAT acceleration not available: {e}")
        return False


def is_sat_available() -> bool:
    """Check if SAT acceleration is available.

    Returns:
        True if SAT backends are available
    """
    return _init_sat()


class SatBagEvaluator:
    """High-level SAT evaluator for CHTD bag constraints.

    Provides automatic SAT/CPU selection based on problem size
    and hardware capabilities.

    Attributes:
        DEFAULT_SAT_THRESHOLD: Minimum variables for SAT use (12)
        sat_threshold: Current threshold for this instance
        max_sat_treewidth: Maximum supported treewidth
    """

    DEFAULT_SAT_THRESHOLD: int = 12

    def __init__(
        self,
        sat_threshold: int = DEFAULT_SAT_THRESHOLD,
        warmup: bool = True,
    ) -> None:
        """Initialize SAT bag evaluator.

        Args:
            sat_threshold: Minimum variables to trigger SAT use
            warmup: Whether to warmup SAT JIT compilation
        """
        self.sat_threshold = sat_threshold
        self._sat_ready = _init_sat()
        self._dispatcher: TieredDispatcher | None = None
        self._backend_info: BackendInfo | None = None
        self.max_sat_treewidth: int = 0

        if self._sat_ready and _sat_module is not None:
            from pysymex.accel import dispatcher as disp_module

            self._dispatcher = disp_module.get_dispatcher()
            self._backend_info = self._dispatcher.get_backend_info()
            self.max_sat_treewidth = self._backend_info.max_treewidth

            if warmup:
                self._warmup()

    def _warmup(self) -> None:
        """Warmup SAT JIT compilation."""
        try:
            from pysymex.accel import dispatcher

            dispatcher.warmup()
        except Exception as e:
            logger.debug(f"SAT warmup failed: {e}")

    @property
    def is_available(self) -> bool:
        """Check if SAT is ready for use."""
        return self._sat_ready

    def get_backend_info(self) -> dict[str, bool | str | int]:
        """Get information about current backend.

        Returns:
            Dict with backend info or just available=False
        """
        if not self._sat_ready or self._backend_info is None:
            return {"available": False}

        return {
            "available": True,
            "backend": self._backend_info.backend_type.name,
            "name": self._backend_info.name,
            "max_treewidth": self._backend_info.max_treewidth,
            "supports_async": self._backend_info.supports_async,
        }

    def should_use_sat(self, num_variables: int) -> bool:
        """Determine if SAT should be used for given variable count.

        Args:
            num_variables: Number of Boolean variables

        Returns:
            True if SAT should be used
        """
        if not self._sat_ready:
            return False

        if num_variables < self.sat_threshold:
            return False

        if num_variables > self.max_sat_treewidth:
            return False

        return True

    def evaluate_bag(
        self,
        constraints: Sequence[z3.ExprRef],
        variables: Sequence[str],
    ) -> npt.NDArray[np.uint8] | None:
        """Evaluate bag constraints using SAT.

        Args:
            constraints: Z3 constraint expressions
            variables: Variable names in order

        Returns:
            Packed bitmap of satisfying assignments, or None if SAT
            should not be used
        """
        import z3

        w = len(variables)

        if not self.should_use_sat(w):
            return None

        if _sat_module is None:
            return None

        from pysymex.accel import bytecode as bytecode_mod

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
                f"SAT evaluated bag w={w}: {result.count_satisfying()} SAT "
                f"in {result.kernel_time_ms:.2f}ms via {result.backend_used.name}"
            )

            return result.bitmap

        except Exception as e:
            logger.warning(f"SAT evaluation failed, falling back to CPU: {e}")
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
                f"Skipping SAT for w={w}: estimated {estimated_ms:.0f}ms "
                f"exceeds timeout {timeout_ms:.0f}ms"
            )
            return None

        return self.evaluate_bag(constraints, variables)

    def _estimate_execution_time(self, num_vars: int, num_constraints: int) -> float:
        """Estimate SAT execution time based on problem size.

        Args:
            num_vars: Number of variables
            num_constraints: Number of constraints

        Returns:
            Estimated milliseconds
        """
        if not self._sat_ready or self._backend_info is None:
            return float("inf")

        num_states = 1 << num_vars

        if self._backend_info.backend_type.name == "SAT":
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


_evaluator: SatBagEvaluator | None = None


def get_bag_evaluator(
    sat_threshold: int = SatBagEvaluator.DEFAULT_SAT_THRESHOLD,
) -> SatBagEvaluator:
    """Get or create global SAT bag evaluator.

    Args:
        sat_threshold: Minimum variables for SAT use

    Returns:
        Singleton evaluator instance
    """
    global _evaluator
    if _evaluator is None:
        _evaluator = SatBagEvaluator(sat_threshold=sat_threshold)
    return _evaluator


def reset() -> None:
    """Reset global evaluator (for testing)."""
    global _evaluator
    _evaluator = None
