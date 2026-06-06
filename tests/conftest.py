"""Global Pytest fixtures for the pysymex test suite.

This module provides high-integrity fixtures for solver instances, memory models,
and directory path resolution. It adheres to the 'no-mocking' policy by using
the actual implementation classes from the pysymex core.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Generator, cast

import pytest

# Force local package import precedence over any installed wheel in site-packages.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
project_root_str = str(PROJECT_ROOT)
if project_root_str not in sys.path:
    sys.path.insert(0, project_root_str)

from pysymex.core.memory.heap.state import MemoryState
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState


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
    from pysymex.core.types.scalars.values import FROM_CONST_CACHE
    from pysymex.core.types.scalars.values import SYMBOLIC_CACHE
    from pysymex.core.types.scalars.values import STRING_CONST_CACHE
    from pysymex.core.types.containers.bytes import BYTES_CONST_CACHE
    from pysymex.core.solver.constraints.literals import clear_exact_bool_literal_cache
    from pysymex.core.solver.constraints.theory import clear_bitvector_theory_cache
    from pysymex.core.solver.engine.context import thread_local_solver
    from pysymex.core.solver.engine.queries import clear_solver_caches
    from pysymex.models.objects import class_registry
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher, OpcodeHandler

    global_handlers = cast(
        "dict[str, OpcodeHandler]", getattr(OpcodeDispatcher, "_global_handlers")
    )
    opcode_handlers_snapshot = dict(global_handlers)

    def reset() -> None:
        SYMBOLIC_CACHE.clear()
        FROM_CONST_CACHE.clear()
        STRING_CONST_CACHE.clear()
        BYTES_CONST_CACHE.clear()
        clear_bitvector_theory_cache()
        clear_exact_bool_literal_cache()
        clear_solver_caches()
        thread_local_solver.solver = None
        class_registry.clear()
        global_handlers.clear()
        global_handlers.update(opcode_handlers_snapshot)

    reset()
    yield
    reset()
