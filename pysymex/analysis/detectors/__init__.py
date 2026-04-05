# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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
