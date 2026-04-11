# PySyMex: Python Symbolic Execution & Formal Verification
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

"""Global Pytest fixtures for the PySyMex test suite.

This module provides high-integrity fixtures for solver instances, memory models,
and directory path resolution. It adheres to the 'no-mocking' policy by using
the actual implementation classes from the pysymex core.
"""

from __future__ import annotations

import pathlib
from typing import Generator

import pytest

from pysymex.core.memory import MemoryState
from pysymex.core.solver.engine import ShadowSolver
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
def solver() -> Generator[ShadowSolver, None, None]:
    """Provide a fresh ShadowSolver instance for each test.
    
    Ensures the Z3 context is clean and properly managed between runs.
    """
    yield ShadowSolver()

@pytest.fixture
def memory() -> MemoryState:
    """Provide a fresh MemoryState instance."""
    return MemoryState()

@pytest.fixture
def state(memory: MemoryState, solver: ShadowSolver) -> VMState:
    """Provide a fully initialized VMState instance with real memory and solver."""
    return VMState(memory=memory, solver=solver)
