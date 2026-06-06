import dis

from pysymex.analysis.static.patterns import (
    NullCoalesceHandler,
    OptionalChainHandler,
    SafeCollectionHandler,
    StringMultiplyHandler,
    TryExceptHandler,
    is_set_of_objects,
    to_string_set,
)
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import PyType, TypeEnvironment


class TestIsSetOfObjects:
    """Tests for is_set_of_objects TypeGuard."""

    def test_set_returns_true(self) -> None:
        assert is_set_of_objects({1, 2}) is True

    def test_list_returns_false(self) -> None:
        assert is_set_of_objects([1, 2]) is False


class TestToStringSet:
    """Tests for to_string_set normalizer."""

    def test_set_of_strings(self) -> None:
        assert to_string_set({"a", "b"}) == {"a", "b"}

    def test_mixed_set_filters(self) -> None:
        assert to_string_set({"a", 1, None}) == {"a"}

    def test_non_set_returns_empty(self) -> None:
        assert to_string_set([1, 2]) == set()


class TestStringMultiplyHandler:
    """Tests for StringMultiplyHandler pattern detection."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.STRING_MULTIPLY in StringMultiplyHandler().pattern_kinds()

    def test_match_returns_none_for_short_sequence(self) -> None:
        handler = StringMultiplyHandler()
        code = compile("x = 1", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        result = handler.match(instructions, len(instructions) - 1, TypeEnvironment())
        assert result is None

    def test_can_raise_error_type_error(self) -> None:
        handler = StringMultiplyHandler()
        match = PatternMatch(PatternKind.STRING_MULTIPLY, 0.95, 0, 4)
        assert handler.can_raise_error(match, "TypeError") is False

    def test_can_raise_error_other(self) -> None:
        handler = StringMultiplyHandler()
        match = PatternMatch(PatternKind.STRING_MULTIPLY, 0.95, 0, 4)
        assert handler.can_raise_error(match, "ValueError") is True


class TestOptionalAndNullHandlers:
    """Tests for optional-chain and null-coalesce handlers."""

    def test_optional_pattern_kinds(self) -> None:
        assert PatternKind.OPTIONAL_CHAIN in OptionalChainHandler().pattern_kinds()

    def test_optional_can_raise_error_attribute(self) -> None:
        handler = OptionalChainHandler()
        match = PatternMatch(PatternKind.OPTIONAL_CHAIN, 0.9, 0, 4)
        assert handler.can_raise_error(match, "AttributeError") is False

    def test_null_pattern_kinds(self) -> None:
        assert PatternKind.NULL_COALESCE in NullCoalesceHandler().pattern_kinds()

    def test_null_match_returns_none_for_non_load(self) -> None:
        handler = NullCoalesceHandler()
        code = compile("1 + 2", "<test>", "exec")
        instructions = list(dis.get_instructions(code))
        assert handler.match(instructions, 0, TypeEnvironment()) is None


class TestSafeCollectionHandler:
    """Tests for SafeCollectionHandler."""

    def test_pattern_kinds(self) -> None:
        kinds = SafeCollectionHandler().pattern_kinds()
        assert PatternKind.LIST_APPEND in kinds
        assert PatternKind.SET_ADD in kinds

    def test_match_list_append_real_bytecode(self) -> None:
        def target(items: list[int]) -> None:
            items.append(1)

        instructions = list(dis.get_instructions(target))
        start_idx = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "LOAD_FAST" and instruction.argval == "items"
        )
        env = TypeEnvironment()
        env.set_type("items", PyType.list_())
        match = SafeCollectionHandler().match(instructions, start_idx, env)
        assert match is not None
        assert match.kind == PatternKind.LIST_APPEND

    def test_rejects_bare_collection_method_without_call(self) -> None:
        def target(items: list[int]) -> object:
            return items.append

        handler = SafeCollectionHandler()
        instructions = list(dis.get_instructions(target))
        start_idx = next(
            index
            for index, instruction in enumerate(instructions)
            if instruction.opname == "LOAD_FAST" and instruction.argval == "items"
        )
        env = TypeEnvironment()
        env.set_type("items", PyType.list_())
        assert handler.match(instructions, start_idx, env) is None

    def test_can_raise_discard_key_error(self) -> None:
        handler = SafeCollectionHandler()
        match = PatternMatch(
            PatternKind.SET_DISCARD,
            0.95,
            0,
            4,
            variables={"method": "discard"},
        )
        assert handler.can_raise_error(match, "KeyError") is False

    def test_can_raise_append_index_error(self) -> None:
        handler = SafeCollectionHandler()
        match = PatternMatch(
            PatternKind.LIST_APPEND,
            0.95,
            0,
            4,
            variables={"method": "append"},
        )
        assert handler.can_raise_error(match, "IndexError") is False


class TestTryExceptHandler:
    """Tests for TryExceptHandler."""

    def test_pattern_kinds(self) -> None:
        assert PatternKind.TRY_EXCEPT_PATTERN in TryExceptHandler().pattern_kinds()

    def test_can_raise_caught_exception(self) -> None:
        handler = TryExceptHandler()
        match = PatternMatch(
            PatternKind.TRY_EXCEPT_PATTERN,
            0.95,
            0,
            4,
            variables={"caught_exceptions": {"ValueError"}},
        )
        assert handler.can_raise_error(match, "ValueError") is False

    def test_can_raise_uncaught_exception(self) -> None:
        handler = TryExceptHandler()
        match = PatternMatch(
            PatternKind.TRY_EXCEPT_PATTERN,
            0.95,
            0,
            4,
            variables={"caught_exceptions": {"ValueError"}},
        )
        assert handler.can_raise_error(match, "TypeError") is True

    def test_can_raise_base_exception_catches_all(self) -> None:
        handler = TryExceptHandler()
        match = PatternMatch(
            PatternKind.TRY_EXCEPT_PATTERN,
            0.95,
            0,
            4,
            variables={"caught_exceptions": {"BaseException"}},
        )
        assert handler.can_raise_error(match, "RuntimeError") is False
