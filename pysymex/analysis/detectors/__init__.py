"""Detectors package — runtime detectors, static detectors, and specialized detectors.

Submodules
----------
base          Core detector ABC, IssueKind, Issue, DetectorRegistry, runtime detectors
static        Static bytecode-based detectors and StaticAnalyzer
specialized   Advanced security-focused detectors (null-deref, injections, etc.)
"""

from __future__ import annotations

from pysymex.analysis.detectors.base import (
    AssertionErrorDetector,
    AttributeErrorDetector,
    Detector,
    DetectorFn,
    DetectorInfo,
    DetectorRegistry,
    DivisionByZeroDetector,
    EnhancedIndexErrorDetector,
    EnhancedTypeErrorDetector,
    FormatStringDetector,
    IndexErrorDetector,
    Issue,
    IssueKind,
    KeyErrorDetector,
    NoneDereferenceDetector,
    OverflowDetector,
    ResourceLeakDetector,
    TaintFlowDetector,
    TypeErrorDetector,
    UnboundVariableDetector,
    ValueErrorDetector,
    default_registry,
)
from pysymex.analysis.detectors.specialized import (
    CommandInjectionDetector,
    InfiniteLoopDetector,
    IntegerOverflowDetector,
    NullDereferenceDetector,
    PathTraversalDetector,
    SQLInjectionDetector,
    UnreachableCodeDetector,
    UseAfterFreeDetector,
    register_advanced_detectors,
)
from pysymex.analysis.detectors.static import (
    StaticAnalyzer,
)

__all__ = [
    "AssertionErrorDetector",
    "AttributeErrorDetector",
    "CommandInjectionDetector",
    "Detector",
    "DetectorFn",
    "DetectorInfo",
    "DetectorRegistry",
    "DivisionByZeroDetector",
    "EnhancedIndexErrorDetector",
    "EnhancedTypeErrorDetector",
    "FormatStringDetector",
    "IndexErrorDetector",
    "InfiniteLoopDetector",
    "IntegerOverflowDetector",
    "Issue",
    "IssueKind",
    "KeyErrorDetector",
    "NoneDereferenceDetector",
    "NullDereferenceDetector",
    "OverflowDetector",
    "PathTraversalDetector",
    "ResourceLeakDetector",
    "SQLInjectionDetector",
    "StaticAnalyzer",
    "TaintFlowDetector",
    "TypeErrorDetector",
    "UnboundVariableDetector",
    "UnreachableCodeDetector",
    "UseAfterFreeDetector",
    "ValueErrorDetector",
    "default_registry",
    "register_advanced_detectors",
]
