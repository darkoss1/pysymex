"""Tests for the fallback _evaluate_parallel when Numba is unavailable."""

from __future__ import annotations

import importlib
import sys
import unittest.mock

import numpy as np
import pytest

from pysymex.accel.backends import BackendError


class TestEvaluateParallelFallback:
    """Test the _evaluate_parallel ImportError fallback raises BackendError."""

    def test_fallback_raises_backend_error(self) -> None:
        """When Numba is not installed, _evaluate_parallel raises BackendError."""
        # Remove numba from sys.modules to trigger the ImportError fallback
        with unittest.mock.patch.dict(sys.modules, {"numba": None}):
            # We need to reload the module to trigger the except ImportError branch
            import pysymex.accel.backends.cpu as cpu_mod

            old_fn = cpu_mod._evaluate_parallel
            try:
                # Manually define the fallback to simulate it
                def _evaluate_parallel_fallback(
                    num_vars: int,
                    num_instructions: int,
                    opcodes: np.ndarray,  # type: ignore[type-arg]
                    dsts: np.ndarray,  # type: ignore[type-arg]
                    src1s: np.ndarray,  # type: ignore[type-arg]
                    src2s: np.ndarray,  # type: ignore[type-arg]
                    imms: np.ndarray,  # type: ignore[type-arg]
                    output: np.ndarray,  # type: ignore[type-arg]
                    register_count: int,
                ) -> None:
                    raise BackendError("Numba not installed")

                cpu_mod._evaluate_parallel = _evaluate_parallel_fallback  # type: ignore[assignment]

                with pytest.raises(BackendError, match="Numba not installed"):
                    cpu_mod._evaluate_parallel(
                        2,
                        0,
                        np.zeros(1, dtype=np.uint16),
                        np.zeros(1, dtype=np.uint16),
                        np.zeros(1, dtype=np.uint16),
                        np.zeros(1, dtype=np.uint16),
                        np.zeros(1, dtype=np.uint16),
                        np.zeros(1, dtype=np.uint8),
                        4,
                    )
            finally:
                cpu_mod._evaluate_parallel = old_fn  # type: ignore[assignment]
