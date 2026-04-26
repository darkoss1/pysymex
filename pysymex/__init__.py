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

"""pysymex package exports (lazy-loaded)."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from pysymex._deps import ensure_z3_ready

if TYPE_CHECKING:
    from pysymex.api import (
        analyze as analyze,
        check_assertions as check_assertions,
        check_division_by_zero as check_division_by_zero,
        quick_check as quick_check,
    )
    from pysymex.scanner import scan_directory as scan_directory, scan_file as scan_file

__version__ = "0.1.0a4"

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
    "analyze": ("pysymex.api", "analyze"),
    "analyze_file": ("pysymex.api", "analyze_file"),
    "analyze_code": ("pysymex.api", "analyze_code"),
    "quick_check": ("pysymex.api", "quick_check"),
    "check_division_by_zero": ("pysymex.api", "check_division_by_zero"),
    "check_assertions": ("pysymex.api", "check_assertions"),
    "check_index_errors": ("pysymex.api", "check_index_errors"),
    "format_issues": ("pysymex.api", "format_issues"),
    "SymbolicExecutor": ("pysymex.execution.executors", "SymbolicExecutor"),
    "ExecutionConfig": ("pysymex.execution.executors", "ExecutionConfig"),
    "ExecutionResult": ("pysymex.execution.executors", "ExecutionResult"),
    "SymbolicValue": ("pysymex.core.types.scalars", "SymbolicValue"),
    "SymbolicString": ("pysymex.core.types.containers", "SymbolicString"),
    "SymbolicList": ("pysymex.core.types.containers", "SymbolicList"),
    "SymbolicDict": ("pysymex.core.types.containers", "SymbolicDict"),
    "SymbolicObject": ("pysymex.core.types.containers", "SymbolicObject"),
    "SymbolicNone": ("pysymex.core.types.scalars", "SymbolicNone"),
    "VMState": ("pysymex.core.state", "VMState"),
    "IncrementalSolver": ("pysymex.core.solver.engine", "IncrementalSolver"),
    "Issue": ("pysymex.analysis.detectors", "Issue"),
    "IssueKind": ("pysymex.analysis.detectors", "IssueKind"),
    "PysymexConfig": ("pysymex.config", "PysymexConfig"),
    "load_config": ("pysymex.config", "load_config"),
    "configure_logging": ("pysymex.logger", "configure_logging"),
    "get_logger": ("pysymex.logger", "get_logger"),
    "LogLevel": ("pysymex.logger", "LogLevel"),
    "format_result": ("pysymex.reporting.formatters", "format_result"),
    "VerifiedExecutor": ("pysymex.execution.executors.verified", "VerifiedExecutor"),
    "VerifiedExecutionConfig": (
        "pysymex.execution.executors.verified",
        "VerifiedExecutionConfig",
    ),
    "VerifiedExecutionResult": (
        "pysymex.execution.executors.verified",
        "VerifiedExecutionResult",
    ),
    "verify": ("pysymex.execution.executors.verified", "verify"),
    "check_contracts": ("pysymex.execution.executors.verified", "check_contracts"),
    "check_arithmetic": ("pysymex.execution.executors.verified", "check_arithmetic"),
    "prove_termination": ("pysymex.execution.executors.verified", "prove_termination"),
    "scan_file": ("pysymex.scanner", "scan_file"),
    "scan_directory": ("pysymex.scanner", "scan_directory"),
    "scan_directory_async": ("pysymex.scanner", "scan_directory_async"),
    "analyze_async": ("pysymex.async_api", "analyze_async"),
    "analyze_code_async": ("pysymex.async_api", "analyze_code_async"),
    "analyze_file_async": ("pysymex.async_api", "analyze_file_async"),
    "Z3Engine": ("pysymex.analysis.solver", "Z3Engine"),
    "Z3Prover": ("pysymex.analysis.solver", "Z3Engine"),
    "CallGraph": ("pysymex.analysis.solver", "CallGraph"),
    "FunctionSummary": ("pysymex.analysis.solver", "FunctionSummary"),
    "BugType": ("pysymex.analysis.solver", "BugType"),
    "Severity": ("pysymex.analysis.solver", "Severity"),
    "VerificationResult": ("pysymex.analysis.solver", "VerificationResult"),
    "CrashCondition": ("pysymex.analysis.solver", "CrashCondition"),
    "verify_function": ("pysymex.analysis.solver", "verify_function"),
    "verify_code": ("pysymex.analysis.solver", "verify_code"),
    "z3_verify_file": ("pysymex.analysis.solver", "verify_file"),
    "z3_verify_directory": ("pysymex.analysis.solver", "verify_directory"),
    "is_z3_available": ("pysymex.analysis.solver", "is_z3_available"),
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

    module_name, attr_name = target
    module = import_module(module_name)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return sorted(set(_EXPORTS.keys()) | {"Z3_AVAILABLE"} | set(globals()))
