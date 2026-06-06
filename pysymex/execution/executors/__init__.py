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

"""Public executor variants for symbolic execution.

This package owns executor implementations and executor-specific helpers.
Execution input policy lives in :mod:`pysymex.execution.config`; execution
output data lives in :mod:`pysymex.execution.results`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.execution.constants import BRANCH_OPCODES

if TYPE_CHECKING:
    from .async_support.runner import (
        AsyncSymbolicExecutor,
    )
    from .concurrent import (
        ConcurrentSymbolicExecutor,
        analyze_concurrent,
    )
    from .core import SymbolicExecutor
    from .verified.api import (
        check_arithmetic,
        check_contracts,
        prove_termination,
        verify,
    )
    from .verified.executor import VerifiedExecutor
    from .verified.types import (
        ArithmeticIssue,
        ContractIssue,
        VerifiedExecutionConfig,
        VerifiedExecutionResult,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "SymbolicExecutor": (".core", "SymbolicExecutor"),
    "VerifiedExecutor": (".verified.executor", "VerifiedExecutor"),
    "VerifiedExecutionConfig": (".verified.types", "VerifiedExecutionConfig"),
    "VerifiedExecutionResult": (".verified.types", "VerifiedExecutionResult"),
    "ContractIssue": (".verified.types", "ContractIssue"),
    "ArithmeticIssue": (".verified.types", "ArithmeticIssue"),
    "verify": (".verified.api", "verify"),
    "check_contracts": (".verified.api", "check_contracts"),
    "check_arithmetic": (".verified.api", "check_arithmetic"),
    "prove_termination": (".verified.api", "prove_termination"),
    "AsyncSymbolicExecutor": (".async_support.runner", "AsyncSymbolicExecutor"),
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

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BRANCH_OPCODES",
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
    "ConcurrentSymbolicExecutor",
    "analyze_concurrent",
]
