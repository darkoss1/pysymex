"""Taint Analysis for PySyMex — slim hub with re-exports.

Extraction modules:
  - checker_types: enums, dataclasses, definitions (TaintKind, SinkKind, etc.)
  - checker_core: TaintAnalyzer, TaintFlowAnalysis, TaintChecker
"""

from pysymex.analysis.taint.checker_core import TaintAnalyzer as TaintAnalyzer

from pysymex.analysis.taint.checker_core import TaintChecker as TaintChecker

from pysymex.analysis.taint.checker_core import TaintFlowAnalysis as TaintFlowAnalysis

from pysymex.analysis.taint.checker_types import Sanitizer as Sanitizer

from pysymex.analysis.taint.checker_types import SinkKind as SinkKind

from pysymex.analysis.taint.checker_types import TaintDefinitions as TaintDefinitions

from pysymex.analysis.taint.checker_types import TaintKind as TaintKind

from pysymex.analysis.taint.checker_types import TaintLabel as TaintLabel

from pysymex.analysis.taint.checker_types import TaintSource as TaintSource

from pysymex.analysis.taint.checker_types import TaintSink as TaintSink

from pysymex.analysis.taint.checker_types import TaintState as TaintState

from pysymex.analysis.taint.checker_types import TaintViolation as TaintViolation

from pysymex.analysis.taint.checker_types import TaintedValue as TaintedValue

__all__ = [
    "Sanitizer",
    "SinkKind",
    "TaintAnalyzer",
    "TaintChecker",
    "TaintDefinitions",
    "TaintFlowAnalysis",
    "TaintKind",
    "TaintLabel",
    "TaintSink",
    "TaintSource",
    "TaintState",
    "TaintViolation",
    "TaintedValue",
]
