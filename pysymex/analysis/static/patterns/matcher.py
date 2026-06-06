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

"""Pattern registry, matcher, analyzer, and result container."""

from __future__ import annotations

import dis
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from types import CodeType

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
from pysymex.analysis.static.types import PyType, TypeEnvironment
from pysymex.core.cache import get_instructions as cached_get_instructions


class PatternRegistry:
    """Registry of all pattern handlers."""

    def __init__(self) -> None:
        self.handlers: list[PatternHandler] = []
        self._kind_to_handlers: dict[PatternKind, list[PatternHandler]] = defaultdict(list)
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register all default pattern handlers."""
        handlers = [
            DictGetHandler(),
            DictSetdefaultHandler(),
            DefaultDictAccessHandler(),
            CounterAccessHandler(),
            SafeIterationHandler(),
            IsinstanceHandler(),
            NoneCheckHandler(),
            HasattrHandler(),
            StringMultiplyHandler(),
            OptionalChainHandler(),
            NullCoalesceHandler(),
            SafeCollectionHandler(),
            TryExceptHandler(),
        ]
        for handler in handlers:
            self.register(handler)

    def register(self, handler: PatternHandler) -> None:
        """Register a pattern handler."""
        self.handlers.append(handler)
        for kind in handler.pattern_kinds():
            self._kind_to_handlers[kind].append(handler)

    def get_handlers_for_kind(self, kind: PatternKind) -> list[PatternHandler]:
        """Get handlers for a specific pattern kind."""
        return self._kind_to_handlers.get(kind, [])


class PatternMatcher:
    """Matches Python patterns in bytecode."""

    def __init__(self, registry: PatternRegistry | None = None) -> None:
        self.registry = registry or PatternRegistry()
        self.cache: dict[int, list[PatternMatch]] = {}

    def find_patterns(
        self,
        instructions: Sequence[dis.Instruction],
        env: TypeEnvironment,
    ) -> list[PatternMatch]:
        """Find all patterns in the instruction sequence."""
        self.clear_cache()
        matches: list[PatternMatch] = []
        for i in range(len(instructions)):
            for handler in self.registry.handlers:
                match = handler.match(instructions, i, env)
                if match:
                    matches.append(match)
                    self.cache.setdefault(match.start_pc, []).append(match)
        return matches

    def get_patterns_at(self, pc: int) -> list[PatternMatch]:
        """Get patterns covering a specific PC."""
        result: list[PatternMatch] = []
        for start_pc, matches in self.cache.items():
            for match in matches:
                if start_pc <= pc <= match.end_pc:
                    result.append(match)
        return result

    def can_error_occur(self, pc: int, error_type: str) -> bool:
        """Check if an error can occur at a PC given active patterns."""
        for match in self.get_patterns_at(pc):
            handlers = self.registry.get_handlers_for_kind(match.kind)
            for handler in handlers:
                if not handler.can_raise_error(match, error_type):
                    return False
        return True

    def get_type_refinements_at(self, pc: int) -> dict[str, PyType]:
        """Get type refinements from patterns at a PC."""
        refinements: dict[str, PyType] = {}
        for match in self.get_patterns_at(pc):
            refinements.update(match.type_refinements)
        return refinements

    def clear_cache(self) -> None:
        """Clear the pattern cache."""
        self.cache.clear()

    def cache_keys(self) -> list[int]:
        """Expose current cache keys for tests and formal checks."""
        return list(self.cache.keys())


class PatternAnalyzer:
    """High-level pattern analyzer for integration with the detector system."""

    def __init__(self) -> None:
        self.registry = PatternRegistry()
        self.matcher = PatternMatcher(self.registry)

    def analyze_function(
        self,
        code: CodeType,
        env: TypeEnvironment | None = None,
    ) -> FunctionPatternInfo:
        """Analyze patterns in a function."""
        instructions = cached_get_instructions(code)
        env = env or TypeEnvironment()
        patterns = self.matcher.find_patterns(instructions, env)
        return FunctionPatternInfo(patterns=patterns, matcher=self.matcher)

    def should_suppress_error(self, pc: int, error_type: str) -> bool:
        """Check if an error should be suppressed at a PC."""
        return not self.matcher.can_error_occur(pc, error_type)


@dataclass
class FunctionPatternInfo:
    """Pattern analysis results for a function."""

    patterns: list[PatternMatch]
    matcher: PatternMatcher

    def get_patterns_at(self, pc: int) -> list[PatternMatch]:
        """Get patterns from this function snapshot that cover a specific PC."""
        return [pattern for pattern in self.patterns if pattern.start_pc <= pc <= pattern.end_pc]

    def get_patterns_by_kind(self, kind: PatternKind) -> list[PatternMatch]:
        """Get patterns of a specific kind."""
        return [pattern for pattern in self.patterns if pattern.kind == kind]

    def has_pattern(self, kind: PatternKind) -> bool:
        """Check if a pattern kind exists."""
        return any(pattern.kind == kind for pattern in self.patterns)

    def can_error_occur(self, pc: int, error_type: str) -> bool:
        """Check if error can occur at PC."""
        for match in self.get_patterns_at(pc):
            handlers = self.matcher.registry.get_handlers_for_kind(match.kind)
            for handler in handlers:
                if not handler.can_raise_error(match, error_type):
                    return False
        return True

    def get_type_refinements(self, pc: int) -> dict[str, PyType]:
        """Get type refinements at PC."""
        refinements: dict[str, PyType] = {}
        for match in self.get_patterns_at(pc):
            refinements.update(match.type_refinements)
        return refinements


__all__ = ["FunctionPatternInfo", "PatternAnalyzer", "PatternMatcher", "PatternRegistry"]
