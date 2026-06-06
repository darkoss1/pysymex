# pysymex: python symbolic execution & formal verification
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

"""Convenience entry points delegating VM execution to ``SymbolicExecutor``."""

from __future__ import annotations

from collections.abc import Callable
from types import CodeType

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.results.result import ExecutionResult


def _create_executor(config: ExecutionConfig | None = None) -> SymbolicExecutor:
    """Return a new executor configured with ``config``."""
    return SymbolicExecutor(config=config)


def execute_function(
    function: Callable[..., object],
    symbolic_args: dict[str, str],
    config: ExecutionConfig | None = None,
) -> ExecutionResult:
    """Delegate symbolic callable execution to a fresh ``SymbolicExecutor``."""
    executor = _create_executor(config)
    return executor.execute_function(function, symbolic_args)


def execute_code(
    code: CodeType,
    symbolic_vars: dict[str, str] | None = None,
    initial_globals: dict[str, object] | None = None,
    config: ExecutionConfig | None = None,
) -> ExecutionResult:
    """Delegate symbolic code-object execution to a fresh ``SymbolicExecutor``."""
    executor = _create_executor(config)
    return executor.execute_code(code, symbolic_vars, initial_globals)
