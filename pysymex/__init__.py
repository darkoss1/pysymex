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

"""pysymex package exports (lazy-loaded)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.deps import ensure_z3_ready
from pysymex.lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.api import (
        ExecutionConfig as ExecutionConfig,
        ExecutionResult as ExecutionResult,
        IncrementalSolver as IncrementalSolver,
        Issue as Issue,
        IssueKind as IssueKind,
        LogLevel as LogLevel,
        PysymexConfig as PysymexConfig,
        SymbolicDict as SymbolicDict,
        SymbolicExecutor as SymbolicExecutor,
        SymbolicList as SymbolicList,
        SymbolicNone as SymbolicNone,
        SymbolicObject as SymbolicObject,
        SymbolicString as SymbolicString,
        SymbolicValue as SymbolicValue,
        VMState as VMState,
        VerifiedExecutionConfig as VerifiedExecutionConfig,
        VerifiedExecutionResult as VerifiedExecutionResult,
        VerifiedExecutor as VerifiedExecutor,
        analyze as analyze,
        analyze_code as analyze_code,
        analyze_file as analyze_file,
        check_arithmetic as check_arithmetic,
        check_assertions as check_assertions,
        check_contracts as check_contracts,
        check_division_by_zero as check_division_by_zero,
        check_index_errors as check_index_errors,
        configure_logging as configure_logging,
        format_issues as format_issues,
        format_result as format_result,
        get_logger as get_logger,
        load_config as load_config,
        prove_termination as prove_termination,
        quick_check as quick_check,
        scan_directory as scan_directory,
        scan_file as scan_file,
        verify as verify,
    )

from pysymex.config import VERSION as _VERSION

__version__ = _VERSION

try:
    ensure_z3_ready()
    avail = True
    err = None
except RuntimeError as exc:
    avail = False
    err = exc

Z3_AVAILABLE: bool = avail
_Z3_IMPORT_ERROR: RuntimeError | None = err

_EXPORTS: dict[str, tuple[str, str]] = {
    "analyze": ("pysymex.api.runtime", "analyze"),
    "analyze_file": ("pysymex.api.runtime", "analyze_file"),
    "analyze_code": ("pysymex.api.runtime", "analyze_code"),
    "quick_check": ("pysymex.api.runtime", "quick_check"),
    "check_division_by_zero": ("pysymex.api.runtime", "check_division_by_zero"),
    "check_assertions": ("pysymex.api.runtime", "check_assertions"),
    "check_index_errors": ("pysymex.api.runtime", "check_index_errors"),
    "format_issues": ("pysymex.api.runtime", "format_issues"),
    "SymbolicExecutor": ("pysymex.api.symbolic", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.config.settings", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.results.result", "ExecutionResult"),
    "SymbolicValue": ("pysymex.api.symbolic", "SymbolicValue"),
    "SymbolicString": ("pysymex.api.symbolic", "SymbolicString"),
    "SymbolicList": ("pysymex.api.symbolic", "SymbolicList"),
    "SymbolicDict": ("pysymex.api.symbolic", "SymbolicDict"),
    "SymbolicObject": ("pysymex.api.symbolic", "SymbolicObject"),
    "SymbolicNone": ("pysymex.api.symbolic", "SymbolicNone"),
    "VMState": ("pysymex.api.symbolic", "VMState"),
    "IncrementalSolver": ("pysymex.api.symbolic", "IncrementalSolver"),
    "Issue": ("pysymex.api.results", "Issue"),
    "IssueKind": ("pysymex.api.results", "IssueKind"),
    "PysymexConfig": ("pysymex.config", "PysymexConfig"),
    "load_config": ("pysymex.config", "load_config"),
    "configure_logging": ("pysymex.api.logging", "configure_logging"),
    "get_logger": ("pysymex.api.logging", "get_logger"),
    "LogLevel": ("pysymex.api.logging", "LogLevel"),
    "format_result": ("pysymex.api.formatting", "format_result"),
    "VerifiedExecutor": ("pysymex.api.verification", "VerifiedExecutor"),
    "VerifiedExecutionConfig": ("pysymex.api.verification", "VerifiedExecutionConfig"),
    "VerifiedExecutionResult": ("pysymex.api.results", "VerifiedExecutionResult"),
    "verify": ("pysymex.api.verification", "verify"),
    "check_contracts": ("pysymex.api.verification", "check_contracts"),
    "check_arithmetic": ("pysymex.api.verification", "check_arithmetic"),
    "prove_termination": ("pysymex.api.verification", "prove_termination"),
    "scan_file": ("pysymex.api.scanning", "scan_file"),
    "scan_directory": ("pysymex.api.runtime", "scan_directory"),
}

_NON_Z3_EXPORTS = {
    "PysymexConfig",
    "load_config",
    "configure_logging",
    "get_logger",
    "LogLevel",
    "Z3_AVAILABLE",
}


def __getattr__(name: str) -> object:
    """Lazy-load package exports to avoid startup side effects."""
    if name == "Z3_AVAILABLE":
        return Z3_AVAILABLE

    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    if _Z3_IMPORT_ERROR is not None and name not in _NON_Z3_EXPORTS:
        raise RuntimeError(str(_Z3_IMPORT_ERROR)) from _Z3_IMPORT_ERROR

    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals(), extra=("Z3_AVAILABLE",))
