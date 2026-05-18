"""Global Pytest fixtures for the pysymex test suite.

This module provides high-integrity fixtures for solver instances, memory models,
and directory path resolution. It adheres to the 'no-mocking' policy by using
the actual implementation classes from the pysymex core.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Generator

import pytest

# Force local package import precedence over any installed wheel in site-packages.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
project_root_str = str(PROJECT_ROOT)
if project_root_str not in sys.path:
    sys.path.insert(0, project_root_str)

from pysymex.core.memory import MemoryState
from pysymex.core.solver.engine import IncrementalSolver
from pysymex.core.state import VMState


@pytest.fixture(scope="session")
def project_root() -> pathlib.Path:
    """Return the absolute path to the project root directory."""
    return pathlib.Path(__file__).parent.parent.absolute()


@pytest.fixture(scope="session")
def fixtures_dir(project_root: pathlib.Path) -> pathlib.Path:
    """Return the absolute path to the static test fixtures directory."""
    return project_root / "tests" / "fixtures"


@pytest.fixture
def solver() -> Generator[IncrementalSolver, None, None]:
    """Provide a fresh IncrementalSolver instance for each test.

    Ensures the Z3 context is clean and properly managed between runs.
    """
    yield IncrementalSolver()


@pytest.fixture
def memory() -> MemoryState:
    """Provide a fresh MemoryState instance."""
    return MemoryState()


@pytest.fixture
def state() -> VMState:
    """Provide a fully initialized VMState instance."""
    return VMState()


@pytest.fixture(autouse=True)
def clean_global_caches() -> Generator[None, None, None]:
    """Clean all global caches before and after each test to ensure total isolation."""
    from pysymex.core.types.scalars import FROM_CONST_CACHE, SYMBOLIC_CACHE, STRING_CONST_CACHE
    from pysymex.core.types.containers import BYTES_CONST_CACHE
    from pysymex.core.solver.engine import clear_solver_caches, _thread_local_solver  # pyright: ignore[reportPrivateUsage]
    from pysymex.core.objects.oop import enhanced_class_registry
    from pysymex.core.memory.addressing import reset as reset_addressing

    SYMBOLIC_CACHE.clear()
    FROM_CONST_CACHE.clear()
    STRING_CONST_CACHE.clear()
    BYTES_CONST_CACHE.clear()
    clear_solver_caches()
    _thread_local_solver.solver = None
    enhanced_class_registry.clear()
    reset_addressing()
    yield
    SYMBOLIC_CACHE.clear()
    FROM_CONST_CACHE.clear()
    STRING_CONST_CACHE.clear()
    BYTES_CONST_CACHE.clear()
    clear_solver_caches()
    _thread_local_solver.solver = None
    enhanced_class_registry.clear()
    reset_addressing()
