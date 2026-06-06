import dis

from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns import (
    FunctionPatternInfo,
    PatternAnalyzer,
    PatternMatcher,
    PatternRegistry,
    StringMultiplyHandler,
)
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment


class _SuppressingStringMultiplyHandler(PatternHandler):
    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.STRING_MULTIPLY}

    def match(
        self,
        instructions: object,
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        _ = instructions, start_idx, env
        return None

    def can_raise_error(self, match: PatternMatch, error_type: str) -> bool:
        _ = match, error_type
        return False


class TestPatternRegistry:
    """Tests for PatternRegistry handler management."""

    def test_default_handlers_registered(self) -> None:
        registry = PatternRegistry()
        assert len(registry.handlers) >= 10

    def test_register_custom_handler(self) -> None:
        registry = PatternRegistry()
        initial_count = len(registry.handlers)
        registry.register(StringMultiplyHandler())
        assert len(registry.handlers) == initial_count + 1

    def test_get_handlers_for_kind(self) -> None:
        registry = PatternRegistry()
        handlers = registry.get_handlers_for_kind(PatternKind.STRING_MULTIPLY)
        assert len(handlers) >= 1

    def test_get_handlers_for_unknown_kind(self) -> None:
        registry = PatternRegistry()
        result = registry.get_handlers_for_kind(PatternKind.LIST_EXTEND)
        assert isinstance(result, list)


class TestPatternMatcher:
    """Tests for PatternMatcher bytecode scanning."""

    def test_init_default_registry(self) -> None:
        matcher = PatternMatcher()
        assert matcher.registry is not None
        assert len(matcher.registry.handlers) >= 10

    def test_find_patterns_simple_code(self) -> None:
        matcher = PatternMatcher()
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        patterns = matcher.find_patterns(instructions, TypeEnvironment())
        assert isinstance(patterns, list)

    def test_get_patterns_at_no_patterns(self) -> None:
        assert PatternMatcher().get_patterns_at(0) == []

    def test_can_error_occur_no_patterns(self) -> None:
        assert PatternMatcher().can_error_occur(0, "TypeError") is True

    def test_get_type_refinements_at_empty(self) -> None:
        assert PatternMatcher().get_type_refinements_at(0) == {}

    def test_clear_cache(self) -> None:
        matcher = PatternMatcher()
        matcher.cache[0] = []
        matcher.clear_cache()
        assert matcher.cache_keys() == []

    def test_cache_keys(self) -> None:
        assert PatternMatcher().cache_keys() == []


class TestPatternAnalyzer:
    """Tests for PatternAnalyzer high-level interface."""

    def test_init(self) -> None:
        analyzer = PatternAnalyzer()
        assert analyzer.registry is not None
        assert analyzer.matcher is not None

    def test_analyze_function(self) -> None:
        analyzer = PatternAnalyzer()
        code = compile("x = 1\ny = 2\n", "<test>", "exec")
        info = analyzer.analyze_function(code)
        assert isinstance(info, FunctionPatternInfo)
        assert isinstance(info.patterns, list)

    def test_should_suppress_error_no_patterns(self) -> None:
        assert PatternAnalyzer().should_suppress_error(0, "TypeError") is False


class TestFunctionPatternInfo:
    """Tests for FunctionPatternInfo dataclass."""

    def test_get_patterns_by_kind(self) -> None:
        matcher = PatternMatcher()
        match1 = PatternMatch(PatternKind.STRING_MULTIPLY, 0.9, 0, 4)
        match2 = PatternMatch(PatternKind.OPTIONAL_CHAIN, 0.9, 0, 4)
        info = FunctionPatternInfo(patterns=[match1, match2], matcher=matcher)
        result = info.get_patterns_by_kind(PatternKind.STRING_MULTIPLY)
        assert len(result) == 1
        assert result[0].kind == PatternKind.STRING_MULTIPLY

    def test_has_pattern_true(self) -> None:
        matcher = PatternMatcher()
        match = PatternMatch(PatternKind.STRING_MULTIPLY, 0.9, 0, 4)
        info = FunctionPatternInfo(patterns=[match], matcher=matcher)
        assert info.has_pattern(PatternKind.STRING_MULTIPLY) is True

    def test_has_pattern_false(self) -> None:
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.has_pattern(PatternKind.STRING_MULTIPLY) is False

    def test_can_error_occur(self) -> None:
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.can_error_occur(0, "TypeError") is True

    def test_can_error_occur_uses_result_patterns_not_mutable_matcher_cache(self) -> None:
        registry = PatternRegistry()
        registry.register(_SuppressingStringMultiplyHandler())
        matcher = PatternMatcher(registry)
        match = PatternMatch(PatternKind.STRING_MULTIPLY, 0.9, 10, 20)
        info = FunctionPatternInfo(patterns=[match], matcher=matcher)
        matcher.clear_cache()

        assert info.can_error_occur(15, "TypeError") is False

    def test_get_type_refinements(self) -> None:
        matcher = PatternMatcher()
        info = FunctionPatternInfo(patterns=[], matcher=matcher)
        assert info.get_type_refinements(0) == {}

    def test_get_type_refinements_uses_result_patterns_not_mutable_matcher_cache(self) -> None:
        matcher = PatternMatcher()
        refined_type = PyType.int_()
        match = PatternMatch(
            PatternKind.NONE_CHECK,
            0.9,
            10,
            20,
            type_refinements={"value": refined_type},
        )
        info = FunctionPatternInfo(patterns=[match], matcher=matcher)
        matcher.clear_cache()

        assert info.get_type_refinements(15) == {"value": refined_type}
