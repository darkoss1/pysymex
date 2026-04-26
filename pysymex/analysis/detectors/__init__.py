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

from __future__ import annotations

from pysymex.analysis.detectors.base import (
    Detector,
    DetectorFn,
    DetectorInfo,
    DetectorRegistry,
    Issue,
    IssueKind,
)

from pysymex.analysis.detectors.runtime.assertion_error import AssertionErrorDetector
from pysymex.analysis.detectors.runtime.attribute_error import AttributeErrorDetector
from pysymex.analysis.detectors.runtime.division_by_zero import DivisionByZeroDetector
from pysymex.analysis.detectors.runtime.enhanced_index_error import EnhancedIndexErrorDetector
from pysymex.analysis.detectors.runtime.enhanced_type_error import EnhancedTypeErrorDetector
from pysymex.analysis.detectors.runtime.index_error import IndexErrorDetector
from pysymex.analysis.detectors.runtime.key_error import KeyErrorDetector
from pysymex.analysis.detectors.runtime.none_dereference import NoneDereferenceDetector
from pysymex.analysis.detectors.runtime.overflow import OverflowDetector
from pysymex.analysis.detectors.runtime.resource_leak import ResourceLeakDetector
from pysymex.analysis.detectors.runtime.type_error import TypeErrorDetector
from pysymex.analysis.detectors.runtime.unbound_variable import UnboundVariableDetector
from pysymex.analysis.detectors.runtime.value_error import ValueErrorDetector

from pysymex.analysis.detectors.specialized.infinite_loop import InfiniteLoopDetector
from pysymex.analysis.detectors.specialized.integer_overflow import IntegerOverflowDetector
from pysymex.analysis.detectors.specialized.null_dereference import NullDereferenceDetector
from pysymex.analysis.detectors.specialized.unreachable_code import UnreachableCodeDetector
from pysymex.analysis.detectors.specialized.use_after_free import UseAfterFreeDetector
from pysymex.analysis.detectors.specialized.format_string import FormatStringDetector

from pysymex.analysis.detectors.static.analyzer import StaticAnalyzer


def _create_default_registry() -> DetectorRegistry:
    """Create default detector registry with all detectors."""
    registry = DetectorRegistry()

    # Runtime detectors
    registry.register(AssertionErrorDetector)
    registry.register(AttributeErrorDetector)
    registry.register(DivisionByZeroDetector)
    registry.register(EnhancedIndexErrorDetector)
    registry.register(EnhancedTypeErrorDetector)
    registry.register(IndexErrorDetector)
    registry.register(KeyErrorDetector)
    registry.register(NoneDereferenceDetector)
    registry.register(OverflowDetector)
    registry.register(ResourceLeakDetector)
    registry.register(TypeErrorDetector)
    registry.register(UnboundVariableDetector)
    registry.register(ValueErrorDetector)

    # Specialized detectors
    registry.register(InfiniteLoopDetector)
    registry.register(IntegerOverflowDetector)
    registry.register(NullDereferenceDetector)
    registry.register(UnreachableCodeDetector)
    registry.register(UseAfterFreeDetector)
    registry.register(FormatStringDetector)

    return registry


default_registry = _create_default_registry()

__all__ = [
    "AssertionErrorDetector",
    "AttributeErrorDetector",
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
    "ResourceLeakDetector",
    "StaticAnalyzer",
    "TypeErrorDetector",
    "UnboundVariableDetector",
    "UnreachableCodeDetector",
    "UseAfterFreeDetector",
    "ValueErrorDetector",
    "default_registry",
]
