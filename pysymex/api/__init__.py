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

"""Primary public API namespace for pysymex."""

from __future__ import annotations

from pysymex.config import AnalysisConfig
from pysymex.api.conversions import to_bool
from pysymex.api.conversions import to_float
from pysymex.api.conversions import to_int
from pysymex.api.formatting import format_result
from pysymex.api.logging import LogLevel
from pysymex.api.logging import configure_logging
from pysymex.api.logging import get_logger
from pysymex.api.results import ExecutionResult
from pysymex.api.results import Issue
from pysymex.api.results import IssueKind
from pysymex.api.results import ScanResult
from pysymex.api.results import VerifiedExecutionResult
from pysymex.api.runtime import analyze
from pysymex.api.runtime import analyze_code
from pysymex.api.runtime import analyze_file
from pysymex.api.runtime import check
from pysymex.api.runtime import check_assertions
from pysymex.api.runtime import check_division_by_zero
from pysymex.api.runtime import check_index_errors
from pysymex.api.runtime import format_issues
from pysymex.api.runtime import quick_check
from pysymex.api.runtime import scan
from pysymex.api.runtime import scan_directory
from pysymex.api.scanning import scan_file
from pysymex.api.symbolic import IncrementalSolver
from pysymex.api.symbolic import SymbolicDict
from pysymex.api.symbolic import SymbolicExecutor
from pysymex.api.symbolic import SymbolicList
from pysymex.api.symbolic import SymbolicNone
from pysymex.api.symbolic import SymbolicObject
from pysymex.api.symbolic import SymbolicString
from pysymex.api.symbolic import SymbolicValue
from pysymex.api.symbolic import VMState
from pysymex.api.verification import VerifiedExecutionConfig
from pysymex.api.verification import VerifiedExecutor
from pysymex.api.verification import check_arithmetic
from pysymex.api.verification import check_contracts
from pysymex.api.verification import prove_termination
from pysymex.api.verification import verify
from pysymex.config import is_object_mapping
from pysymex.config import load_config
from pysymex.config import PysymexConfig
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.strategies.manager.types import ExplorationStrategy

__all__ = [
    "AnalysisConfig",
    "ExecutionConfig",
    "ExecutionResult",
    "ExplorationStrategy",
    "IncrementalSolver",
    "Issue",
    "IssueKind",
    "LogLevel",
    "PysymexConfig",
    "ScanResult",
    "SymbolicDict",
    "SymbolicExecutor",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicObject",
    "SymbolicString",
    "SymbolicValue",
    "VMState",
    "VerifiedExecutionConfig",
    "VerifiedExecutionResult",
    "VerifiedExecutor",
    "analyze",
    "analyze_code",
    "analyze_file",
    "check",
    "check_arithmetic",
    "check_assertions",
    "check_contracts",
    "check_division_by_zero",
    "check_index_errors",
    "configure_logging",
    "format_issues",
    "format_result",
    "get_logger",
    "is_object_mapping",
    "load_config",
    "prove_termination",
    "quick_check",
    "scan",
    "scan_directory",
    "scan_file",
    "to_bool",
    "to_float",
    "to_int",
    "verify",
]
