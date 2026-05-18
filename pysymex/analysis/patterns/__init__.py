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

"""Public exports for Python bytecode pattern analysis."""

from __future__ import annotations

from pysymex.analysis.patterns.core import (
    CounterAccessHandler,
    DefaultDictAccessHandler,
    DictGetHandler,
    DictSetdefaultHandler,
    HasattrHandler,
    IsinstanceHandler,
    NoneCheckHandler,
    PatternHandler,
    PatternKind,
    PatternMatch,
    SafeIterationHandler,
)
from pysymex.analysis.patterns.handlers import (
    FunctionPatternInfo,
    NullCoalesceHandler,
    OptionalChainHandler,
    PatternAnalyzer,
    PatternMatcher,
    PatternRegistry,
    SafeCollectionHandler,
    StringMultiplyHandler,
    TryExceptHandler,
)
from pysymex.analysis.type_inference import PyType, TypeEnvironment, TypeKind
from pysymex._guards import is_set_of_objects as _is_set_of_objects
from pysymex._typing import to_string_set as _to_string_set

__all__ = [
    "CounterAccessHandler",
    "DefaultDictAccessHandler",
    "DictGetHandler",
    "DictSetdefaultHandler",
    "FunctionPatternInfo",
    "HasattrHandler",
    "IsinstanceHandler",
    "NoneCheckHandler",
    "NullCoalesceHandler",
    "OptionalChainHandler",
    "PatternAnalyzer",
    "PatternHandler",
    "PatternKind",
    "PatternMatch",
    "PatternMatcher",
    "PatternRegistry",
    "SafeCollectionHandler",
    "SafeIterationHandler",
    "StringMultiplyHandler",
    "TryExceptHandler",
    "PyType",
    "TypeEnvironment",
    "TypeKind",
    "_is_set_of_objects",
    "_to_string_set",
]
