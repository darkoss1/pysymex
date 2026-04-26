"""Tests for pysymex.analysis.patterns — bytecode pattern matching."""

from __future__ import annotations

import dis

from pysymex.analysis.patterns import (
    FunctionPatternInfo,
    NullCoalesceHandler,
    OptionalChainHandler,
    PatternAnalyzer,
    PatternMatcher,
    PatternRegistry,
    SafeCollectionHandler,
    StringMultiplyHandler,
    TryExceptHandler,
    _is_set_of_objects,
    _to_string_set,
)
from pysymex.analysis.patterns.core import (
    PatternKind,
    PatternMatch,
)
from pysymex.analysis.type_inference import TypeEnvironment


class TestIsSetOfObjects:
    """Tests for _is_set_of_objects TypeGuard."""

    def test_set_returns_true(self) -> None:
        """A set passes."""
        assert _is_set_of_objects({1, 2}) is True

    def test_list_returns_false(self) -> None:
        """A list does not pass."""
        assert _is_set_of_objects([1, 2]) is False


class TestToStringSet:
    """Tests for _to_string_set normalizer."""

    def test_set_of_strings(self) -> None:
        """Converts set of strings correctly."""
        result = _to_string_set({"a", "b"})
        assert result == {"a", "b"}

    def test_mixed_set_filters(self) -> None:
        """Non-string items are filtered out."""
        result = _to_string_set({"a", 1, None})
        assert result == {"a"}

    def test_non_set_returns_empty(self) -> None:
        """Non-set input returns empty set."""
        result = _to_string_set([1, 2])
        assert result == set()


class TestStringMultiplyHandler:
    """Tests for StringMultiplyHandler pattern detection."""

    def test_pattern_kinds(self) -> None:
        """Returns STRING_MULTIPLY kind."""
        handler = StringMultiplyHandler()
        assert PatternKind.STRING_MULTIPLY in handler.pattern_kinds()

    def test_match_returns_none_for_short_sequence(self) -> None:
        """Match returns None for too-short instruction sequences."""
        handler = StringMultiplyHandler()
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        env = TypeEnvironment()
        result = handler.match(instructions, len(instructions) - 1, env)
        assert result is None

    def test_can_raise_error_type_error(self) -> None:
        """TypeError is suppressed for string multiply."""
        handler = StringMultiplyHandler()
        match = PatternMatch(
            kind=PatternKind.STRING_MULTIPLY,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
        )
        assert handler.can_raise_error(match, "TypeError") is False

    def test_can_raise_error_other(self) -> None:
        """Non-TypeError errors are not suppressed."""
        handler = StringMultiplyHandler()
        match = PatternMatch(
            kind=PatternKind.STRING_MULTIPLY,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
        )
        assert handler.can_raise_error(match, "ValueError") is True


class TestOptionalChainHandler:
    """Tests for OptionalChainHandler pattern detection."""

    def test_pattern_kinds(self) -> None:
        """Returns OPTIONAL_CHAIN kind."""
        handler = OptionalChainHandler()
        assert PatternKind.OPTIONAL_CHAIN in handler.pattern_kinds()

    def test_can_raise_error_attribute(self) -> None:
        """AttributeError is suppressed."""
        handler = OptionalChainHandler()
        match = PatternMatch(
            kind=PatternKind.OPTIONAL_CHAIN,
            confidence=0.9,
            start_pc=0,
            end_pc=4,
        )
        assert handler.can_raise_error(match, "AttributeError") is False


class TestNullCoalesceHandler:
    """Tests for NullCoalesceHandler."""

    def test_pattern_kinds(self) -> None:
        """Returns NULL_COALESCE kind."""
        handler = NullCoalesceHandler()
        assert PatternKind.NULL_COALESCE in handler.pattern_kinds()

    def test_match_returns_none_for_non_load(self) -> None:
        """Match returns None when first instruction isn't a load."""
        handler = NullCoalesceHandler()
        code = compile("1 + 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        env = TypeEnvironment()
        result = handler.match(instructions, 0, env)
        assert result is None


class TestSafeCollectionHandler:
    """Tests for SafeCollectionHandler."""

    def test_pattern_kinds(self) -> None:
        """Returns list/set operation kinds."""
        handler = SafeCollectionHandler()
        kinds = handler.pattern_kinds()
        assert PatternKind.LIST_APPEND in kinds
        assert PatternKind.SET_ADD in kinds

    def test_can_raise_discard_key_error(self) -> None:
        """discard suppresses KeyError."""
        handler = SafeCollectionHandler()
        match = PatternMatch(
            kind=PatternKind.SET_DISCARD,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
            variables={"method": "discard"},
        )
        assert handler.can_raise_error(match, "KeyError") is False

    def test_can_raise_append_index_error(self) -> None:
        """append suppresses IndexError."""
        handler = SafeCollectionHandler()
        match = PatternMatch(
            kind=PatternKind.LIST_APPEND,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
            variables={"method": "append"},
        )
        assert handler.can_raise_error(match, "IndexError") is False


class TestTryExceptHandler:
    """Tests for TryExceptHandler."""

    def test_pattern_kinds(self) -> None:
        """Returns TRY_EXCEPT_PATTERN kind."""
        handler = TryExceptHandler()
        assert PatternKind.TRY_EXCEPT_PATTERN in handler.pattern_kinds()

    def test_can_raise_caught_exception(self) -> None:
        """Caught exception type is suppressed."""
        handler = TryExceptHandler()
        match = PatternMatch(
            kind=PatternKind.TRY_EXCEPT_PATTERN,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
            variables={"caught_exceptions": {"ValueError"}},
        )
        assert handler.can_raise_error(match, "ValueError") is False

    def test_can_raise_uncaught_exception(self) -> None:
        """Uncaught exception type is not suppressed."""
        handler = TryExceptHandler()
        match = PatternMatch(
            kind=PatternKind.TRY_EXCEPT_PATTERN,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
            variables={"caught_exceptions": {"ValueError"}},
        )
        assert handler.can_raise_error(match, "TypeError") is True

    def test_can_raise_base_exception_catches_all(self) -> None:
        """BaseException in caught set suppresses everything."""
        handler = TryExceptHandler()
        match = PatternMatch(
            kind=PatternKind.TRY_EXCEPT_PATTERN,
            confidence=0.95,
            start_pc=0,
            end_pc=4,
            variables={"caught_exceptions": {"BaseException"}},
        )
        assert handler.can_raise_error(match, "RuntimeError") is False


class TestPatternRegistry:
    """Tests for PatternRegistry handler management."""

    def test_default_handlers_registered(self) -> None:
        """Registry has default handlers after init."""
        registry = PatternRegistry()
        assert len(registry.handlers) >= 10

    def test_register_custom_handler(self) -> None:
        """register() adds a custom handler."""
        registry = PatternRegistry()
        initial_count = len(registry.handlers)
        handler = StringMultiplyHandler()
        registry.register(handler)
        assert len(registry.handlers) == initial_count + 1

    def test_get_handlers_for_kind(self) -> None:
        """get_handlers_for_kind returns handlers for a specific kind."""
        registry = PatternRegistry()
        handlers = registry.get_handlers_for_kind(PatternKind.STRING_MULTIPLY)
        assert len(handlers) >= 1

    def test_get_handlers_for_unknown_kind(self) -> None:
        """get_handlers_for_kind returns empty list for kind with no handlers."""
        registry = PatternRegistry()
        # Use a valid PatternKind but one that has few/no dedicated handlers
        result = registry.get_handlers_for_kind(PatternKind.LIST_EXTEND)
        assert isinstance(result, list)


class TestPatternMatcher:
    """Tests for PatternMatcher bytecode scanning."""

    def test_init_default_registry(self) -> None:
        """PatternMatcher creates its own registry if none provided."""
        matcher = PatternMatcher()
        assert matcher.registry is not None
        assert len(matcher.registry.handlers) >= 10

    def test_find_patterns_simple_code(self) -> None:
        """find_patterns on simple code returns a (possibly empty) list."""
        matcher = PatternMatcher()
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        env = TypeEnvironment()
        patterns = matcher.find_patterns(instructions, env)
        assert isinstance(patterns, list)

    def test_get_patterns_at_no_patterns(self) -> None:
        """get_patterns_at returns empty when no patterns at PC."""
        matcher = PatternMatcher()
        result = matcher.get_patterns_at(0)
        assert result == []

    def test_can_error_occur_no_patterns(self) -> None:
        """can_error_occur returns True when no patterns suppress it."""
        matcher = PatternMatcher()
        assert matcher.can_error_occur(0, "TypeError") is True

    def test_get_type_refinements_at_empty(self) -> None:
        """get_type_refinements_at returns empty dict when no patterns."""
        matcher = PatternMatcher()
        result = matcher.get_type_refinements_at(0)
        assert result == {}

    def test_clear_cache(self) -> None:
        """clear_cache empties the cache."""
        matcher = PatternMatcher()
        matcher._cache[0] = []
        matcher.clear_cache()
        assert matcher.cache_keys() == []

    def test_cache_keys(self) -> None:
        """cache_keys returns current cache keys."""
        matcher = PatternMatcher()
        assert matcher.cache_keys() == []


class TestPatternAnalyzer:
    """Tests for PatternAnalyzer high-level interface."""

    def test_init(self) -> None:
        """PatternAnalyzer initializes with registry and matcher."""
        analyzer = PatternAnalyzer()
        assert analyzer.registry is not None
        assert analyzer.matcher is not None

    def test_analyze_function(self) -> None:
        """analyze_function returns FunctionPatternInfo."""
        analyzer = PatternAnalyzer()
        code = compile("x = 1\ny = 2\n", "<test>", "exec")
        info = analyzer.analyze_function(code)
        assert isinstance(info, FunctionPatternInfo)
        assert isinstance(info.patterns, list)

    def test_should_suppress_error_no_patterns(self) -> None:
        """should_suppress_error returns False when no patterns active."""
        analyzer = PatternAnalyzer()
        assert analyzer.should_suppress_error(0, "TypeError") is False


class TestFunctionPatternInfo:
    """Tests for FunctionPatternInfo dataclass."""

    def test_get_patterns_by_kind(self) -> None:
        """get_patterns_by_kind filters patterns."""
        matcher = PatternMatcher()
        match1 = PatternMatch(
            kind=PatternKind.STRING_MULTIPLY, confidence=0.9, start_pc=0, end_pc=4
        )
        match2 = PatternMatch(kind=PatternKind.OPTIONAL_CHAIN, confidence=0.9, start_pc=0, end_pc=4)
        info = FunctionPatternInfo(patterns=[match1, match2], matcher=matcher)
        result = info.get_patterns_by_kind(PatternKind.STRING_MULTIPLY)
        assert len(result) == 1
        assert result[0].kind == PatternKind.STRING_MULTIPLY

    def test_has_pattern_true(self) -> None:
        """has_pattern returns True when pattern exists."""
        matcher = PatternMatcher()
        match = PatternMatch(kind=PatternKind.STRING_MULTIPLY, confidence=0.9, start_pc=0, end_pc=4)
        info = FunctionPatternInfo(patterns=[match], matcher=matcher)
        assert info.has_pattern(PatternKind.STRING_MULTIPLY) is True

    def test_has_pattern_false(self) -> None:
        """has_pattern returns False when pattern doesn't exist."""
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.has_pattern(PatternKind.STRING_MULTIPLY) is False

    def test_can_error_occur(self) -> None:
        """can_error_occur delegates to matcher."""
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.can_error_occur(0, "TypeError") is True

    def test_get_type_refinements(self) -> None:
        """get_type_refinements delegates to matcher."""
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.get_type_refinements(0) == {}
