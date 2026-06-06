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

"""Specialized detectors package.

Aggregates specialized/security detectors such as null dereference, infinite loop,
use-after-free, integer overflow, format string, and unreachable code.

Bug Class Detected:
    Runtime and logical anomalies.

Required Evidence:
    Satisfiable execution states violating specialized safety properties.

Issue Kinds:
    IssueKind.NULL_DEREFERENCE, IssueKind.INFINITE_LOOP, IssueKind.ATTRIBUTE_ERROR,
    IssueKind.OVERFLOW, IssueKind.INVALID_ARGUMENT, IssueKind.UNREACHABLE_CODE
"""

from .null_dereference import NullDereferenceDetector
from .infinite_loop import InfiniteLoopDetector
from .use_after_free import UseAfterFreeDetector
from .format_string import FormatStringDetector
from .unreachable_code import UnreachableCodeDetector

__all__ = [
    "NullDereferenceDetector",
    "InfiniteLoopDetector",
    "UseAfterFreeDetector",
    "FormatStringDetector",
    "UnreachableCodeDetector",
]
