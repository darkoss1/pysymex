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

"""
Executor variants for symbolic execution.

This package provides various symbolic execution engines:
- SymbolicExecutor: Core engine for sequential execution.
- VerifiedExecutor: Formal verification engine with contract checking.
- AsyncSymbolicExecutor: Engine for asyncio/coroutine analysis.
- ConcurrentSymbolicExecutor: Engine for multi-threaded/concurrent analysis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.types import BRANCH_OPCODES, ExecutionConfig, ExecutionResult

if TYPE_CHECKING:
    from .async_exec import (
        AsyncSymbolicExecutor as AsyncSymbolicExecutor,
        analyze_async as analyze_async,
    )
    from .concurrent import (
        ConcurrentSymbolicExecutor as ConcurrentSymbolicExecutor,
        analyze_concurrent as analyze_concurrent,
    )
    from .core import SymbolicExecutor as SymbolicExecutor
    from .verified import (
        ArithmeticIssue as ArithmeticIssue,
        ContractIssue as ContractIssue,
        VerifiedExecutionConfig as VerifiedExecutionConfig,
        VerifiedExecutionResult as VerifiedExecutionResult,
        VerifiedExecutor as VerifiedExecutor,
        check_arithmetic as check_arithmetic,
        check_contracts as check_contracts,
        prove_termination as prove_termination,
        verify as verify,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "SymbolicExecutor": (".core", "SymbolicExecutor"),
    "VerifiedExecutor": (".verified", "VerifiedExecutor"),
    "VerifiedExecutionConfig": (".verified", "VerifiedExecutionConfig"),
    "VerifiedExecutionResult": (".verified", "VerifiedExecutionResult"),
    "ContractIssue": (".verified", "ContractIssue"),
    "ArithmeticIssue": (".verified", "ArithmeticIssue"),
    "verify": (".verified", "verify"),
    "check_contracts": (".verified", "check_contracts"),
    "check_arithmetic": (".verified", "check_arithmetic"),
    "prove_termination": (".verified", "prove_termination"),
    "AsyncSymbolicExecutor": (".async_exec", "AsyncSymbolicExecutor"),
    "analyze_async": (".async_exec", "analyze_async"),
    "ConcurrentSymbolicExecutor": (".concurrent", "ConcurrentSymbolicExecutor"),
    "analyze_concurrent": (".concurrent", "analyze_concurrent"),
}


def __getattr__(name: str) -> object:
    """Lazy-load executors and related utilities."""
    if name in _EXPORTS:
        from importlib import import_module

        module_path, attr_name = _EXPORTS[name]
        module = import_module(module_path, __package__)
        return getattr(module, attr_name)

    if name == "BRANCH_OPCODES":
        return BRANCH_OPCODES
    if name == "ExecutionConfig":
        return ExecutionConfig
    if name == "ExecutionResult":
        return ExecutionResult

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BRANCH_OPCODES",
    "ExecutionConfig",
    "ExecutionResult",
    "SymbolicExecutor",
    "VerifiedExecutor",
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "ContractIssue",
    "ArithmeticIssue",
    "verify",
    "check_contracts",
    "check_arithmetic",
    "prove_termination",
    "AsyncSymbolicExecutor",
    "analyze_async",
    "ConcurrentSymbolicExecutor",
    "analyze_concurrent",
]
