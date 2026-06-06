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

"""Runtime exception detectors package.

Aggregates detectors for runtime Python exceptions, such as division by zero, type/attribute/key errors,
index errors, assertions, resource leaks, overflows, and unbound variables.

Bug Class Detected:
    Runtime exceptions.

Required Evidence:
    Satisfiable execution states violating safety assertions.

Issue Kinds:
    IssueKind.DIVISION_BY_ZERO, IssueKind.NULL_DEREFERENCE, IssueKind.KEY_ERROR,
    IssueKind.INDEX_ERROR, IssueKind.TYPE_ERROR, IssueKind.ATTRIBUTE_ERROR,
    IssueKind.ASSERTION_ERROR, IssueKind.RESOURCE_LEAK, IssueKind.OVERFLOW,
    IssueKind.UNBOUND_VARIABLE, IssueKind.NAME_ERROR
"""

from .division_by_zero import DivisionByZeroDetector
from .errors.assertion import AssertionErrorDetector
from .index_error.detector import IndexErrorDetector
from .errors.key import KeyErrorDetector
from .errors.type import TypeErrorDetector
from .errors.attribute import AttributeErrorDetector
from .overflow import OverflowDetector
from .resource_leak import ResourceLeakDetector
from .value_error import ValueErrorDetector
from .none_dereference import NoneDereferenceDetector
from .unbound_variable import UnboundVariableDetector

__all__ = [
    "DivisionByZeroDetector",
    "AssertionErrorDetector",
    "IndexErrorDetector",
    "KeyErrorDetector",
    "TypeErrorDetector",
    "AttributeErrorDetector",
    "OverflowDetector",
    "ResourceLeakDetector",
    "ValueErrorDetector",
    "NoneDereferenceDetector",
    "UnboundVariableDetector",
]
