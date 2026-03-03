"""
Exception Modeling for pysymex.

Hub module — re-exports from:
  exceptions_types   : data classes, enums, @raises decorator
  exceptions_analyzer: ExceptionAnalyzer, helper functions, BUILTIN_EXCEPTIONS
"""

from pysymex.core.exceptions_types import (
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

from pysymex.core.exceptions_analyzer import (
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

__all__ = [
    "ExceptionCategory",
    "EXCEPTION_CATEGORIES",
    "get_exception_category",
    "SymbolicException",
    "ExceptionHandler",
    "FinallyHandler",
    "TryBlock",
    "ExceptionPath",
    "ExceptionState",
    "RaisesContract",
    "raises",
    "ExceptionAnalyzer",
    "create_exception_from_opcode",
    "propagate_exception",
    "merge_exception_states",
    "check_precondition_violation",
    "check_postcondition_violation",
    "check_invariant_violation",
    "BUILTIN_EXCEPTIONS",
    "is_builtin_exception",
    "get_exception_hierarchy",
]
