"""Global Pytest fixtures for the pysymex test suite.

This module provides high-integrity fixtures for solver instances, memory models,
and directory path resolution. It adheres to the 'no-mocking' policy by using
the actual implementation classes from the pysymex core.
"""

from __future__ import annotations

import pathlib
from typing import Generator

import pytest

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
