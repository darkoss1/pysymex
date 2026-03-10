"""Taint analysis package — taint tracking and taint-flow checking.

Submodules
----------
core      Taint sources/sinks, labels, flows, tracker, basic analyzer
checker   Flow-sensitive taint checker with CFG-based data-flow analysis
"""

from __future__ import annotations

from pysymex.analysis.taint.checker import (
    TaintChecker,
    TaintViolation,
)
from pysymex.analysis.taint.core import (
    TaintAnalyzer,
    TaintedValue,
    TaintFlow,
    TaintLabel,
    TaintPolicy,
    TaintSink,
    TaintSource,
    TaintTracker,
)

__all__ = [
    "TaintAnalyzer",
    "TaintChecker",
    "TaintFlow",
    "TaintLabel",
    "TaintPolicy",
    "TaintSink",
    "TaintSource",
    "TaintTracker",
    "TaintViolation",
    "TaintedValue",
]
