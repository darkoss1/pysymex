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

from pysymex._internal.analysis.detectors.detector.registry import DetectorRegistry
from pysymex._internal.analysis.detectors.runtime.division.zero import DivisionByZeroDetector
from pysymex._internal.analysis.detectors.runtime.errors.assertion import AssertionErrorDetector
from pysymex._internal.analysis.detectors.runtime.errors.attribute.detector import (
    AttributeErrorDetector,
)
from pysymex._internal.analysis.detectors.runtime.errors.key import KeyErrorDetector
from pysymex._internal.analysis.detectors.runtime.errors.type import TypeErrorDetector
from pysymex._internal.analysis.detectors.runtime.indexing.detector import IndexErrorDetector
from pysymex._internal.analysis.detectors.runtime.none.dereference import NoneDereferenceDetector
from pysymex._internal.analysis.detectors.runtime.overflow import OverflowDetector
from pysymex._internal.analysis.detectors.runtime.resource.leak import ResourceLeakDetector
from pysymex._internal.analysis.detectors.runtime.unbound.variable import UnboundVariableDetector
from pysymex._internal.analysis.detectors.runtime.user.exception import UserExceptionDetector
from pysymex._internal.analysis.detectors.runtime.value.detector import ValueErrorDetector
from pysymex._internal.analysis.detectors.specialized.formatting import FormatStringDetector
from pysymex._internal.analysis.detectors.specialized.loops import InfiniteLoopDetector
from pysymex._internal.analysis.detectors.specialized.resources import UseAfterFreeDetector


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
    registry.register(UseAfterFreeDetector)
    registry.register(FormatStringDetector)

    return registry


default_registry = _create_default_registry()
