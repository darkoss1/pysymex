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

"""Public exports for the advanced Z3 verification engine."""

from __future__ import annotations

from pysymex.analysis.solver.analyzer import FunctionAnalyzer
from pysymex.analysis.solver.engine import (
    Z3Engine,
    deserialize_worker_results as _deserialize_worker_results,
    estimate_complexity,
    is_z3_available,
    verify_code,
    verify_directory,
    verify_file,
    verify_function,
)
from pysymex.analysis.solver.graph import CallGraph, CFGBuilder, SymbolicState
from pysymex.analysis.solver.types import (
    Z3_AVAILABLE,
    BasicBlock,
    BugType,
    CallSite,
    CrashCondition,
    FunctionSummary,
    Severity,
    SymType,
    SymValue,
    VerificationResult,
)
from pysymex._guards import is_dict_of_objects as _is_dict_of_objects

__all__ = [
    "Z3_AVAILABLE",
    "BasicBlock",
    "BugType",
    "CFGBuilder",
    "CallGraph",
    "CallSite",
    "CrashCondition",
    "FunctionAnalyzer",
    "FunctionSummary",
    "Severity",
    "SymType",
    "SymValue",
    "SymbolicState",
    "VerificationResult",
    "Z3Engine",
    "_deserialize_worker_results",
    "_is_dict_of_objects",
    "estimate_complexity",
    "is_z3_available",
    "verify_code",
    "verify_directory",
    "verify_file",
    "verify_function",
]
