"""Tests for Week 4 detection improvements.

Tests cover:
- None-check awareness
- Exception handler detection
- Smart bound detection integration
"""

from pysymex.analysis.exceptions.handler import (
    ExceptionHandlerAnalyzer,
    ExceptionHandlerInfo,
    ExceptionHandlerState,
    ExceptionHandlerType,
    should_skip_issue_in_handler,
)

from pysymex.analysis.none_check import (
    NoneCheck,
    NoneCheckAnalyzer,
    NoneCheckState,
    NoneCheckType,
    extract_variable_from_expression,
    is_none_check_in_message,
)


class TestNoneCheckState:
    """Test None check state tracking."""

    def test_mark_not_none(self):
        """Marking as not None should update state correctly."""

        state = NoneCheckState()

        state.mark_not_none("x")

        assert state.is_known_not_none("x")

        assert not state.is_known_none("x")

    def test_mark_none(self):
        """Marking as None should update state correctly."""

        state = NoneCheckState()

        state.mark_none("x")

        assert state.is_known_none("x")

        assert not state.is_known_not_none("x")

    def test_mark_unchecked(self):
        """Marking as unchecked should clear other states."""

        state = NoneCheckState()

        state.mark_not_none("x")

        state.mark_unchecked("x")

        assert not state.is_known_not_none("x")

        assert not state.is_known_none("x")

    def test_copy(self):
        """Copy should create independent state."""

        state = NoneCheckState()

        state.mark_not_none("x")

        copy = state.copy()

        copy.mark_none("x")

        assert state.is_known_not_none("x")

        assert copy.is_known_none("x")

    def test_merge_keeps_confirmed_in_both(self):
        """Merge should only keep what's confirmed in both states."""

        state1 = NoneCheckState()

        state1.mark_not_none("x")

        state1.mark_not_none("y")

        state2 = NoneCheckState()

        state2.mark_not_none("x")

        state2.mark_not_none("z")

        merged = state1.merge(state2)

        assert merged.is_known_not_none("x")

        assert not merged.is_known_not_none("y")

        assert not merged.is_known_not_none("z")


class TestNoneCheckAnalyzer:
    """Test None check analysis."""

    def test_analyze_is_not_none(self):
        """Should detect 'is not None' checks."""

        analyzer = NoneCheckAnalyzer()

        checks = analyzer.analyze_source("if x is not None: pass")

        assert len(checks) >= 1

        assert any(c.check_type == NoneCheckType.IS_NOT_NONE for c in checks)

    def test_analyze_is_none(self):
        """Should detect 'is None' checks."""

        analyzer = NoneCheckAnalyzer()

        checks = analyzer.analyze_source("if x is None: pass")

        assert len(checks) >= 1

        assert any(c.check_type == NoneCheckType.IS_NONE for c in checks)

    def test_analyze_not_equals_none(self):
        """Should detect '!= None' checks."""

        analyzer = NoneCheckAnalyzer()

        checks = analyzer.analyze_source("if x != None: pass")

        assert len(checks) >= 1

        assert any(c.check_type == NoneCheckType.NOT_EQUALS_NONE for c in checks)

    def test_analyze_equals_none(self):
        """Should detect '== None' checks."""

        analyzer = NoneCheckAnalyzer()

        checks = analyzer.analyze_source("if x == None: pass")

        assert len(checks) >= 1

        assert any(c.check_type == NoneCheckType.EQUALS_NONE for c in checks)

    def test_update_state_for_is_not_none_true_branch(self):
        """True branch of 'is not None' confirms not None."""

        analyzer = NoneCheckAnalyzer()

        check = NoneCheck("x", NoneCheckType.IS_NOT_NONE)

        analyzer.update_state_for_check(check, in_true_branch=True)

        assert analyzer.is_none_safe("x")

    def test_update_state_for_is_not_none_false_branch(self):
        """False branch of 'is not None' confirms None."""

        analyzer = NoneCheckAnalyzer()

        check = NoneCheck("x", NoneCheckType.IS_NOT_NONE)

        analyzer.update_state_for_check(check, in_true_branch=False)

        assert analyzer.get_state().is_known_none("x")

    def test_update_state_for_is_none_true_branch(self):
        """True branch of 'is None' confirms None."""

        analyzer = NoneCheckAnalyzer()

        check = NoneCheck("x", NoneCheckType.IS_NONE)

        analyzer.update_state_for_check(check, in_true_branch=True)

        assert analyzer.get_state().is_known_none("x")

    def test_update_state_for_is_none_false_branch(self):
        """False branch of 'is None' confirms not None."""

        analyzer = NoneCheckAnalyzer()

        check = NoneCheck("x", NoneCheckType.IS_NONE)

        analyzer.update_state_for_check(check, in_true_branch=False)

        assert analyzer.is_none_safe("x")


class TestExceptionHandlerState:
    """Test exception handler state tracking."""

    def test_enter_handler(self):
        """Entering handler should add to active list."""

        state = ExceptionHandlerState()

        handler = ExceptionHandlerInfo(
            handler_type=ExceptionHandlerType.EXCEPT,
            start_pc=10,
            end_pc=20,
        )

        state.enter_handler(handler)

        assert state.is_in_handler()

        assert state.current_handler() is handler

    def test_exit_handler(self):
        """Exiting handler should remove from active list."""

        state = ExceptionHandlerState()

        handler = ExceptionHandlerInfo(
            handler_type=ExceptionHandlerType.EXCEPT,
            start_pc=10,
            end_pc=20,
        )

        state.enter_handler(handler)

        exited = state.exit_handler()

        assert exited is handler

        assert not state.is_in_handler()

    def test_nested_handlers(self):
        """Should track nested handlers correctly."""

        state = ExceptionHandlerState()

        handler1 = ExceptionHandlerInfo(
            handler_type=ExceptionHandlerType.EXCEPT,
            start_pc=10,
            end_pc=30,
        )

        handler2 = ExceptionHandlerInfo(
            handler_type=ExceptionHandlerType.FINALLY,
            start_pc=15,
            end_pc=25,
        )

        state.enter_handler(handler1)

        state.enter_handler(handler2)

        assert state.current_handler() is handler2

        assert state.is_in_finally()

        state.exit_handler()

        assert state.current_handler() is handler1

        assert not state.is_in_finally()


class TestExceptionHandlerAnalyzer:
    """Test exception handler analysis."""

    def test_analyze_simple_try_except(self):
        """Should detect simple try/except."""

        analyzer = ExceptionHandlerAnalyzer()

        source = """
try:
    x = 1
except:
    pass
"""

        handlers = analyzer.analyze_source(source)

        assert len(handlers) >= 1

        assert any(h.handler_type == ExceptionHandlerType.EXCEPT for h in handlers)

    def test_analyze_except_with_type(self):
        """Should detect except with specific type."""

        analyzer = ExceptionHandlerAnalyzer()

        source = """
try:
    x = 1
except ValueError:
    pass
"""

        handlers = analyzer.analyze_source(source)

        assert any(
            h.handler_type == ExceptionHandlerType.EXCEPT_TYPE and "ValueError" in h.exception_types
            for h in handlers
        )

    def test_analyze_except_as(self):
        """Should detect except with 'as' clause."""

        analyzer = ExceptionHandlerAnalyzer()

        source = """
try:
    x = 1
except ValueError as e:
    print(e)
"""

        handlers = analyzer.analyze_source(source)

        assert any(
            h.handler_type == ExceptionHandlerType.EXCEPT_AS and h.exception_var == "e"
            for h in handlers
        )

    def test_analyze_finally(self):
        """Should detect finally blocks."""

        analyzer = ExceptionHandlerAnalyzer()

        source = """
try:
    x = 1
finally:
    cleanup()
"""

        handlers = analyzer.analyze_source(source)

        assert any(h.handler_type == ExceptionHandlerType.FINALLY for h in handlers)

    def test_analyze_try_else(self):
        """Should detect try/else blocks."""

        analyzer = ExceptionHandlerAnalyzer()

        source = """
try:
    x = 1
except:
    pass
else:
    success()
"""

        handlers = analyzer.analyze_source(source)

        assert any(h.handler_type == ExceptionHandlerType.ELSE for h in handlers)


class TestHelperFunctions:
    """Test helper functions."""

    def test_extract_variable_simple(self):
        """Should extract simple variable names."""

        assert extract_variable_from_expression("x") == "x"

    def test_extract_variable_from_attribute(self):
        """Should extract base variable from attribute."""

        assert extract_variable_from_expression("x.y.z") == "x"

    def test_extract_variable_from_subscript(self):
        """Should extract base variable from subscript."""

        assert extract_variable_from_expression("x[0]") == "x"

    def test_is_none_check_in_message_positive(self):
        """Should detect None-related messages."""

        is_none, var = is_none_check_in_message("'x' may be None")

        assert is_none

        assert var == "x"

    def test_is_none_check_in_message_negative(self):
        """Should not detect non-None messages."""

        is_none, _ = is_none_check_in_message("Division by zero")

        assert not is_none

    def test_should_skip_unreachable_in_handler(self):
        """Should skip unreachable code in handlers."""

        handlers = [
            ExceptionHandlerInfo(
                handler_type=ExceptionHandlerType.EXCEPT,
                start_pc=10,
                end_pc=20,
            )
        ]

        assert should_skip_issue_in_handler(15, "UNREACHABLE_CODE", handlers)

        assert not should_skip_issue_in_handler(25, "UNREACHABLE_CODE", handlers)

        assert not should_skip_issue_in_handler(15, "DIVISION_BY_ZERO", handlers)
