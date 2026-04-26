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

"""Exception modeling public exports."""

from pysymex.core.exceptions.analyzer import (
    BUILTIN_EXCEPTIONS,
    ExceptionAnalyzer,
    check_invariant_violation,
    check_postcondition_violation,
    check_precondition_violation,
    create_exception_from_opcode,
    get_exception_hierarchy,
    is_builtin_exception,
    merge_exception_states,
    propagate_exception,
)
from pysymex.core.exceptions.types import (
    EXCEPTION_CATEGORIES,
    ExceptionCategory,
    ExceptionHandler,
    ExceptionPath,
    ExceptionState,
    FinallyHandler,
    RaisesContract,
    SymbolicException,
    TryBlock,
    get_exception_category,
    raises,
)

__all__ = [
    "BUILTIN_EXCEPTIONS",
    "EXCEPTION_CATEGORIES",
    "ExceptionAnalyzer",
    "ExceptionCategory",
    "ExceptionHandler",
    "ExceptionPath",
    "ExceptionState",
    "FinallyHandler",
    "RaisesContract",
    "SymbolicException",
    "TryBlock",
    "check_invariant_violation",
    "check_postcondition_violation",
    "check_precondition_violation",
    "create_exception_from_opcode",
    "get_exception_category",
    "get_exception_hierarchy",
    "is_builtin_exception",
    "merge_exception_states",
    "propagate_exception",
    "raises",
]
