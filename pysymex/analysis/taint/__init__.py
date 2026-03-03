"""Taint analysis package — taint tracking and taint-flow checking.

Submodules
----------
core      Taint sources/sinks, labels, flows, tracker, basic analyzer
checker   Flow-sensitive taint checker with CFG-based data-flow analysis
"""

from __future__ import annotations


from pysymex.analysis.taint.core import (
    TaintAnalyzer,
    TaintFlow,
    TaintLabel,
    TaintPolicy,
    TaintSink,
    TaintSource,
    TaintTracker,
    TaintedValue,
)


from pysymex.analysis.taint.checker import (
    TaintChecker,
    TaintViolation,
)

__all__ = [
    "TaintAnalyzer",
    "TaintFlow",
    "TaintLabel",
    "TaintPolicy",
    "TaintSink",
    "TaintSource",
    "TaintTracker",
    "TaintedValue",
    "TaintChecker",
    "TaintViolation",
]
