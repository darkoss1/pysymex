"""Global Pytest fixtures for the pysymex test suite.

This module provides high-integrity fixtures for solver instances, memory models,
and directory path resolution. It adheres to the 'no-mocking' policy by using
the actual implementation classes from the pysymex core.
"""

from __future__ import annotations

import pathlib
import sys
from typing import cast
from collections.abc import Generator

import pytest

# Force local package import precedence over any installed wheel in site-packages.
PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
project_root_str = str(PROJECT_ROOT)
if project_root_str not in sys.path:
    sys.path.insert(0, project_root_str)

from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState

_PYTEST_RUNTIME_ROOT_NAME = ".tmp"
_PYTEST_RUNTIME_DIR = PROJECT_ROOT / _PYTEST_RUNTIME_ROOT_NAME / "pytest"
_PYTEST_BASETEMP_DIR = _PYTEST_RUNTIME_DIR / "tmp"


def centralized_pytest_basetemp(raw_basetemp: object) -> pathlib.Path | None:
    """Return the centralized basetemp for relative root ``.pytest_*`` overrides."""
    if raw_basetemp is None:
        return None
    basetemp = pathlib.Path(str(raw_basetemp))
    if basetemp.is_absolute() or not basetemp.parts:
        return None
    if basetemp.parts[0] == _PYTEST_RUNTIME_ROOT_NAME:
        return None
    if not basetemp.parts[0].startswith(".pytest_"):
        return None
    return _PYTEST_BASETEMP_DIR.joinpath(*basetemp.parts)


def pytest_configure(config: pytest.Config) -> None:
    """Keep relative pytest scratch directories inside ``.tmp/pytest``."""
    centralized_basetemp = centralized_pytest_basetemp(config.option.basetemp)
    if centralized_basetemp is not None:
        config.option.basetemp = str(centralized_basetemp)


@pytest.fixture(scope="session")
def project_root() -> pathlib.Path:
    """Return the absolute path to the project root directory."""
    return pathlib.Path(__file__).parent.parent.absolute()


@pytest.fixture(scope="session")
def fixtures_dir(project_root: pathlib.Path) -> pathlib.Path:
    """Return the absolute path to the static test fixtures directory."""
    return project_root / "tests" / "fixtures"


@pytest.fixture
def solver() -> Generator[IncrementalSolver]:
    """Provide a fresh IncrementalSolver instance for each test.

    Ensures the Z3 context is clean and properly managed between runs.
    """
    yield IncrementalSolver()


@pytest.fixture
def state() -> VMState:
    """Provide a fully initialized VMState instance."""
    return VMState()


@pytest.fixture(autouse=True)
def clean_global_caches() -> Generator[None]:
    """Clean all global caches before and after each test to ensure total isolation."""
    from pysymex._internal.core.classes.registry import class_registry
    from pysymex._internal.core.solver.constraints.exact.literal.cache import (
        clear_exact_bool_literal_cache,
    )
    from pysymex._internal.core.solver.constraints.theory import clear_bitvector_theory_cache
    from pysymex._internal.core.solver.engine.context import thread_local_solver
    from pysymex._internal.core.types.containers.bytes import BYTES_CONST_CACHE
    from pysymex._internal.core.types.scalars.value.scalar_ops import (
        FROM_CONST_CACHE,
        STRING_CONST_CACHE,
        SYMBOLIC_CACHE,
    )
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

    global_handlers = cast("dict[str, object]", getattr(OpcodeDispatcher, "_global_handlers"))
    opcode_handlers_snapshot = dict(global_handlers)

    def reset() -> None:
        SYMBOLIC_CACHE.clear()
        FROM_CONST_CACHE.clear()
        STRING_CONST_CACHE.clear()
        BYTES_CONST_CACHE.clear()
        clear_bitvector_theory_cache()
        clear_exact_bool_literal_cache()
        thread_local_solver.solver = None
        thread_local_solver.model_solver = None
        class_registry.clear()
        global_handlers.clear()
        global_handlers.update(opcode_handlers_snapshot)

    reset()
    yield
    reset()
