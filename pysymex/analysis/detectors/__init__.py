# pysymex: python symbolic execution & formal verification
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

"""PySymex detectors package.

This package exposes the default registry and all built-in static, runtime,
and specialized bug detectors.

Detectors registered in this package check for various bug classes including:
- ZeroDivisionError (DivisionByZeroDetector)
- IndexError (IndexErrorDetector)
- KeyError (KeyErrorDetector)
- AttributeError / None dereference (NoneDereferenceDetector, AttributeErrorDetector)
- AssertionError (AssertionErrorDetector)
- TypeError (TypeErrorDetector)
- ValueError (ValueErrorDetector)
- Use after free / Resource leaks (UseAfterFreeDetector, ResourceLeakDetector)
"""

from __future__ import annotations

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.registry import DetectorRegistry
from pysymex.analysis.detectors.detector.types import (
    DetectorFn,
    DetectorInfo,
    GetModelFn,
    IsSatFn,
    Issue,
    IssueKind,
    Severity,
)

from pysymex.analysis.detectors.runtime.errors.assertion import AssertionErrorDetector
from pysymex.analysis.detectors.runtime.errors.attribute import AttributeErrorDetector
from pysymex.analysis.detectors.runtime.division_by_zero import DivisionByZeroDetector
from pysymex.analysis.detectors.runtime.index_error.detector import IndexErrorDetector
from pysymex.analysis.detectors.runtime.errors.key import KeyErrorDetector
from pysymex.analysis.detectors.runtime.none_dereference import NoneDereferenceDetector
from pysymex.analysis.detectors.runtime.overflow import OverflowDetector
from pysymex.analysis.detectors.runtime.resource_leak import ResourceLeakDetector
from pysymex.analysis.detectors.runtime.errors.type import TypeErrorDetector
from pysymex.analysis.detectors.runtime.unbound_variable import UnboundVariableDetector
from pysymex.analysis.detectors.runtime.user_exception import UserExceptionDetector
from pysymex.analysis.detectors.runtime.value_error import ValueErrorDetector

from pysymex.analysis.detectors.specialized.infinite_loop import InfiniteLoopDetector
from pysymex.analysis.detectors.specialized.null_dereference import NullDereferenceDetector
from pysymex.analysis.detectors.specialized.unreachable_code import UnreachableCodeDetector
from pysymex.analysis.detectors.specialized.use_after_free import UseAfterFreeDetector
from pysymex.analysis.detectors.specialized.format_string import FormatStringDetector


def _create_default_registry() -> DetectorRegistry:
    """Create default detector registry with all detectors."""
    registry = DetectorRegistry()

    # Runtime detectors
    registry.register(AssertionErrorDetector)
    registry.register(AttributeErrorDetector)
    registry.register(DivisionByZeroDetector)
    registry.register(IndexErrorDetector)
    registry.register(KeyErrorDetector)
    registry.register(NoneDereferenceDetector)
    registry.register(OverflowDetector)
    registry.register(ResourceLeakDetector)
    registry.register(TypeErrorDetector)
    registry.register(UnboundVariableDetector)
    registry.register(UserExceptionDetector)
    registry.register(ValueErrorDetector)

    # Specialized detectors
    registry.register(InfiniteLoopDetector)
    # Runtime OverflowDetector subsumes bounded-overflow semantics.
    # registry.register(NullDereferenceDetector)  # Redundant with NoneDereferenceDetector + AttributeErrorDetector
    # UNREACHABLE_CODE is handled by dedicated dead-code/static analyses.
    # Keeping it out of the default runtime registry avoids symbolic-path
    # approximation false positives on reachable code.
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
    "FormatStringDetector",
    "GetModelFn",
    "IndexErrorDetector",
    "InfiniteLoopDetector",
    "IsSatFn",
    "Issue",
    "IssueKind",
    "Severity",
    "KeyErrorDetector",
    "NoneDereferenceDetector",
    "NullDereferenceDetector",
    "OverflowDetector",
    "ResourceLeakDetector",
    "TypeErrorDetector",
    "UnboundVariableDetector",
    "UnreachableCodeDetector",
    "UseAfterFreeDetector",
    "UserExceptionDetector",
    "ValueErrorDetector",
    "default_registry",
]
