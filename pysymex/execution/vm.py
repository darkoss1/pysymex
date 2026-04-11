# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

"""Execution VM entry points.

The bytecode VM loop is implemented by SymbolicExecutor. This module provides
an explicit blueprint-level VM access surface under execution/vm.py.
"""

from __future__ import annotations

from collections.abc import Callable
from types import CodeType

from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig, ExecutionResult

__all__ = ["SymbolicExecutor", "execute_function", "execute_code"]


def execute_function(
    function: Callable[..., object],
    symbolic_args: dict[str, str],
    config: ExecutionConfig | None = None,
) -> ExecutionResult:
    """Execute a Python callable symbolically through the VM engine."""
    executor = SymbolicExecutor(config=config)
    return executor.execute_function(function, symbolic_args)


def execute_code(
    code: CodeType,
    symbolic_vars: dict[str, str] | None = None,
    initial_globals: dict[str, object] | None = None,
    config: ExecutionConfig | None = None,
) -> ExecutionResult:
    """Execute a code object symbolically through the VM engine."""
    executor = SymbolicExecutor(config=config)
    return executor.execute_code(code, symbolic_vars, initial_globals)
