import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.none import (
    NoneCheckType,
    NoneCheck,
    NoneCheckState,
    NoneCheckAnalyzer,
    apply_none_check,
    extract_variable_from_expression,
    is_none_check_in_message,
)


class TestNoneCheckType:
    """Test suite for pysymex.analysis.specialized.none.NoneCheckType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert NoneCheckType.IS_NONE.name == "IS_NONE"
        assert NoneCheckType.IS_NOT_NONE.name == "IS_NOT_NONE"


class TestNoneCheck:
    """Test suite for pysymex.analysis.specialized.none.NoneCheck."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        c = NoneCheck("x", NoneCheckType.IS_NONE)
        assert c.variable_name == "x"
        assert c.check_type == NoneCheckType.IS_NONE


class TestNoneCheckState:
    """Test suite for pysymex.analysis.specialized.none.NoneCheckState."""

    def test_mark_not_none(self) -> None:
        """Test mark_not_none behavior."""
        state = NoneCheckState()
        state.mark_not_none("x")
        assert state.is_known_not_none("x") is True

    def test_mark_none(self) -> None:
        """Test mark_none behavior."""
        state = NoneCheckState()
        state.mark_none("x")
        assert state.is_known_none("x") is True

    def test_mark_unchecked(self) -> None:
        """Test mark_unchecked behavior."""
        state = NoneCheckState()
        state.mark_none("x")
        state.mark_unchecked("x")
        assert state.is_known_none("x") is False

    def test_is_known_not_none(self) -> None:
        """Test is_known_not_none behavior."""
        state = NoneCheckState()
        assert state.is_known_not_none("x") is False

    def test_is_known_none(self) -> None:
        """Test is_known_none behavior."""
        state = NoneCheckState()
        assert state.is_known_none("x") is False

    def test_copy(self) -> None:
        """Test copy behavior."""
        state = NoneCheckState()
        state.mark_none("x")
        c = state.copy()
        assert c.is_known_none("x") is True
        assert c is not state

    def test_merge(self) -> None:
        """Test merge behavior."""
        s1 = NoneCheckState()
        s1.mark_none("x")
        s1.mark_not_none("y")
        s2 = NoneCheckState()
        s2.mark_none("x")
        s2.mark_none("y")
        merged = s1.merge(s2)
        assert merged.is_known_none("x") is True
        assert merged.is_known_not_none("y") is False


class TestNoneCheckAnalyzer:
    """Test suite for pysymex.analysis.specialized.none.NoneCheckAnalyzer."""

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = NoneCheckAnalyzer()
        source = "if x is None: pass"
        checks = analyzer.analyze_source(source)
        assert len(checks) == 1
        assert checks[0].variable_name == "x"

    def test_analyze_ast_condition(self) -> None:
        """Test analyze_ast_condition behavior."""
        import ast

        analyzer = NoneCheckAnalyzer()
        node = ast.parse("x is None").body[0].value
        check = analyzer.analyze_ast_condition(node)
        assert check is not None
        assert check.variable_name == "x"
        assert check.check_type == NoneCheckType.IS_NONE

    def test_update_state_for_check(self) -> None:
        """Test update_state_for_check behavior."""
        analyzer = NoneCheckAnalyzer()
        state = NoneCheckState()
        analyzer.set_state(state)
        analyzer.update_state_for_check(NoneCheck("x", NoneCheckType.IS_NONE), True)
        assert analyzer.get_state().is_known_none("x") is True

        state2 = NoneCheckState()
        analyzer.set_state(state2)
        analyzer.update_state_for_check(NoneCheck("x", NoneCheckType.IS_NONE), False)
        assert analyzer.get_state().is_known_not_none("x") is True

    def test_is_none_safe(self) -> None:
        """Test is_none_safe behavior."""
        analyzer = NoneCheckAnalyzer()
        assert analyzer.is_none_safe("x") is False

    def test_get_state(self) -> None:
        """Test get_state behavior."""
        analyzer = NoneCheckAnalyzer()
        assert isinstance(analyzer.get_state(), NoneCheckState)

    def test_set_state(self) -> None:
        """Test set_state behavior."""
        analyzer = NoneCheckAnalyzer()
        state = NoneCheckState()
        analyzer.set_state(state)
        assert analyzer.get_state() is state


def test_apply_none_check() -> None:
    """Test apply_none_check behavior."""
    state = NoneCheckState()
    new_state = apply_none_check(state, NoneCheck("x", NoneCheckType.IS_NONE), True)
    assert new_state.is_known_none("x") is True


def test_extract_variable_from_expression() -> None:
    """Test extract_variable_from_expression behavior."""
    assert extract_variable_from_expression("self.x") == "self"
    assert extract_variable_from_expression("x[0]") == "x"
    assert extract_variable_from_expression("x") == "x"


def test_is_none_check_in_message() -> None:
    """Test is_none_check_in_message behavior."""
    is_none, var = is_none_check_in_message("'x' may be None")
    assert is_none is True
    assert var == "x"

    is_none2, var2 = is_none_check_in_message("x == 1")
    assert is_none2 is False
