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

"""Execution module for pysymex.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.
"""

from __future__ import annotations

from importlib import import_module

_EXPORTS: dict[str, tuple[str, str]] = {
    "ExecutionContext": ("pysymex.execution.protocols", "ExecutionContext"),
    "execute_function": ("pysymex.execution.vm", "execute_function"),
    "execute_code": ("pysymex.execution.vm", "execute_code"),
    "OpcodeDispatcher": ("pysymex.execution.dispatcher", "OpcodeDispatcher"),
    "OpcodeResult": ("pysymex.execution.dispatcher", "OpcodeResult"),
    "opcode_handler": ("pysymex.execution.dispatcher", "opcode_handler"),
    "SymbolicExecutor": ("pysymex.execution.executors", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.executors", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.executors", "ExecutionResult"),
    "analyze": ("pysymex.api", "analyze"),
    "analyze_code": ("pysymex.api", "analyze_code"),
    "quick_check": ("pysymex.api", "quick_check"),
    "VerifiedExecutor": ("pysymex.execution.executors.verified", "VerifiedExecutor"),
    "VerifiedExecutionConfig": ("pysymex.execution.executors.verified", "VerifiedExecutionConfig"),
    "VerifiedExecutionResult": ("pysymex.execution.executors.verified", "VerifiedExecutionResult"),
    "TerminationStatus": ("pysymex.execution.executors.verified", "TerminationStatus"),
    "TerminationProof": ("pysymex.execution.executors.verified", "TerminationProof"),
    "RankingFunction": ("pysymex.execution.executors.verified", "RankingFunction"),
    "TerminationAnalyzer": ("pysymex.execution.executors.verified", "TerminationAnalyzer"),
    "ContractIssue": ("pysymex.execution.executors.verified", "ContractIssue"),
    "ArithmeticIssue": ("pysymex.execution.executors.verified", "ArithmeticIssue"),
    "InferredProperty": ("pysymex.execution.executors.verified", "InferredProperty"),
    "verify": ("pysymex.execution.executors.verified", "verify"),
    "check_contracts": ("pysymex.execution.executors.verified", "check_contracts"),
    "check_arithmetic": ("pysymex.execution.executors.verified", "check_arithmetic"),
    "prove_termination": ("pysymex.execution.executors.verified", "prove_termination"),
    "AsyncSymbolicExecutor": ("pysymex.execution.executors.async_exec", "AsyncSymbolicExecutor"),
    "SymbolicEventLoop": ("pysymex.execution.executors.async_exec", "SymbolicEventLoop"),
    "analyze_async": ("pysymex.execution.executors.async_exec", "analyze_async"),
    "ConcurrentSymbolicExecutor": (
        "pysymex.execution.executors.concurrent",
        "ConcurrentSymbolicExecutor",
    ),
    "analyze_concurrent": ("pysymex.execution.executors.concurrent", "analyze_concurrent"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.execution' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())
