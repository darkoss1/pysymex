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

"""Public exports for Python bytecode pattern analysis."""

from __future__ import annotations

from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.handlers.collection import SafeCollectionHandler
from pysymex.analysis.static.patterns.dict.access import (
    CounterAccessHandler,
    DefaultDictAccessHandler,
)
from pysymex.analysis.static.patterns.dict.methods import DictGetHandler, DictSetdefaultHandler
from pysymex.analysis.static.patterns.handlers.exception import TryExceptHandler
from pysymex.analysis.static.patterns.iteration import SafeIterationHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.patterns.matcher import (
    FunctionPatternInfo,
    PatternAnalyzer,
    PatternMatcher,
    PatternRegistry,
)
from pysymex.analysis.static.patterns.handlers.optional import (
    NullCoalesceHandler,
    OptionalChainHandler,
)
from pysymex.analysis.static.patterns.handlers.string import StringMultiplyHandler
from pysymex.analysis.static.patterns.type_guards import (
    HasattrHandler,
    IsinstanceHandler,
    NoneCheckHandler,
)
from pysymex.analysis.static.types import PyType, TypeEnvironment, TypeKind
from pysymex.guards import is_set_of_objects
from pysymex.typing import to_string_set

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
    "is_set_of_objects",
    "to_string_set",
]
