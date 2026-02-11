"""
Z3 Formal Verification Engine for Python Bytecode
=================================================
This module provides backwards compatibility with the original z3_prover API.
The actual implementation has been moved to z3_engine.py which provides:
- Interprocedural analysis with call graph tracking
- Function summaries for efficient re-analysis
- Taint tracking for security analysis
- Intelligent path exploration
See z3_engine.py for the full implementation.
SAT = Bug CAN occur (with counterexample showing exact crash values)
UNSAT = Bug CANNOT occur (mathematically proven safe)
"""

from __future__ import annotations
from pyspectre.analysis.z3_engine import (
    Z3_AVAILABLE,
    BasicBlock,
    BugType,
    CallGraph,
    CallSite,
    CFGBuilder,
    CrashCondition,
    FunctionAnalyzer,
    FunctionSummary,
    Severity,
    SymbolicState,
    SymType,
    SymValue,
    TaintInfo,
    TaintSource,
    VerificationResult,
    Z3Engine,
    is_z3_available,
    verify_code,
    verify_directory,
    verify_file,
    verify_function,
)

Z3Prover = Z3Engine
__all__ = [
    "BugType",
    "Severity",
    "SymType",
    "TaintSource",
    "SymValue",
    "CrashCondition",
    "VerificationResult",
    "FunctionSummary",
    "CallSite",
    "BasicBlock",
    "TaintInfo",
    "CallGraph",
    "CFGBuilder",
    "SymbolicState",
    "FunctionAnalyzer",
    "Z3Engine",
    "Z3Prover",
    "verify_function",
    "verify_code",
    "verify_file",
    "verify_directory",
    "is_z3_available",
    "Z3_AVAILABLE",
]
