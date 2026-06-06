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

"""Lazy public namespace for VM execution, dispatch, results, and analyzers."""

from __future__ import annotations

from pysymex.lazy import lazy_dir, lazy_getattr

_EXPORTS: dict[str, tuple[str, str]] = {
    "ExecutionContext": ("pysymex.execution.protocols", "ExecutionContext"),
    "execute_function": ("pysymex.execution.vm", "execute_function"),
    "execute_code": ("pysymex.execution.vm", "execute_code"),
    "OpcodeDispatcher": ("pysymex.execution.dispatch.dispatcher", "OpcodeDispatcher"),
    "OpcodeResult": ("pysymex.execution.dispatch.result", "OpcodeResult"),
    "opcode_handler": ("pysymex.execution.dispatch.dispatcher", "opcode_handler"),
    "SymbolicExecutor": ("pysymex.execution.executors", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.config.settings", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.results.result", "ExecutionResult"),
    "VerifiedExecutor": ("pysymex.execution.executors.verified.executor", "VerifiedExecutor"),
    "VerifiedExecutionConfig": (
        "pysymex.execution.executors.verified.types",
        "VerifiedExecutionConfig",
    ),
    "VerifiedExecutionResult": (
        "pysymex.execution.executors.verified.types",
        "VerifiedExecutionResult",
    ),
    "TerminationStatus": ("pysymex.execution.termination", "TerminationStatus"),
    "TerminationProof": ("pysymex.execution.termination", "TerminationProof"),
    "RankingFunction": ("pysymex.execution.termination", "RankingFunction"),
    "TerminationAnalyzer": ("pysymex.execution.termination", "TerminationAnalyzer"),
    "ContractIssue": ("pysymex.execution.executors.verified.types", "ContractIssue"),
    "ArithmeticIssue": ("pysymex.execution.executors.verified.types", "ArithmeticIssue"),
    "InferredProperty": ("pysymex.execution.executors.verified.types", "InferredProperty"),
    "verify": ("pysymex.execution.executors.verified.api", "verify"),
    "check_contracts": ("pysymex.execution.executors.verified.api", "check_contracts"),
    "check_arithmetic": ("pysymex.execution.executors.verified.api", "check_arithmetic"),
    "prove_termination": ("pysymex.execution.executors.verified.api", "prove_termination"),
    "AsyncSymbolicExecutor": (
        "pysymex.execution.executors.async_support.runner",
        "AsyncSymbolicExecutor",
    ),
    "SymbolicEventLoop": ("pysymex.execution.executors.async_support.runner", "SymbolicEventLoop"),
    "ConcurrentSymbolicExecutor": (
        "pysymex.execution.executors.concurrent",
        "ConcurrentSymbolicExecutor",
    ),
    "analyze_concurrent": ("pysymex.execution.executors.concurrent", "analyze_concurrent"),
}


def __getattr__(name: str) -> object:
    """Resolve a registered execution export on first attribute access."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Return lazily exported execution names for introspection."""
    return lazy_dir(_EXPORTS, globals(), include_namespace=False)
