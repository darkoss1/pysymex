from types import CodeType

from pysymex.analysis.domains.exceptions.handler import (
    ExceptionHandlerType,
    ExceptionHandlerInfo,
    ExceptionHandlerState,
    ExceptionHandlerAnalyzer,
    should_skip_issue_in_handler,
)


def make_dummy_code() -> CodeType:
    def f() -> None:
        try:
            pass
        except ValueError:
            pass
        finally:
            pass

    return f.__code__


class TestExceptionHandlerType:
    """Test suite for pysymex.analysis.domains.exceptions.handler.ExceptionHandlerType."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ExceptionHandlerType.EXCEPT.name == "EXCEPT"
        assert ExceptionHandlerType.FINALLY.name == "FINALLY"


class TestExceptionHandlerInfo:
    """Test suite for pysymex.analysis.domains.exceptions.handler.ExceptionHandlerInfo."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = ExceptionHandlerInfo(ExceptionHandlerType.EXCEPT, 10, 20)
        assert info.handler_type == ExceptionHandlerType.EXCEPT
        assert info.start_pc == 10
        assert info.end_pc == 20


class TestExceptionHandlerState:
    """Test suite for pysymex.analysis.domains.exceptions.handler.ExceptionHandlerState."""

    def test_initialization(self) -> None:
        """Test initial state."""
        state = ExceptionHandlerState()
        assert state.all_handlers == []


class TestExceptionHandlerAnalyzer:
    """Test suite for pysymex.analysis.domains.exceptions.handler.ExceptionHandlerAnalyzer."""

    def test_analyze_bytecode(self) -> None:
        """Test analyze_bytecode behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        code = make_dummy_code()
        handlers = analyzer.analyze_bytecode(code)
        assert isinstance(handlers, list)
        assert len(handlers) > 0

    def test_analyze_source(self) -> None:
        """Test analyze_source behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        source = """
try:
    pass
except ValueError as e:
    pass
else:
    pass
finally:
    pass
        """
        handlers = analyzer.analyze_source(source)
        assert len(handlers) == 3

    def test_is_pc_in_handler(self) -> None:
        """Test is_pc_in_handler behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        analyzer.get_state().all_handlers.append(
            ExceptionHandlerInfo(ExceptionHandlerType.EXCEPT, 10, 20)
        )
        assert analyzer.is_pc_in_handler(15) is True
        assert analyzer.is_pc_in_handler(5) is False

    def test_is_line_in_handler(self) -> None:
        """Test is_line_in_handler behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        analyzer.get_state().all_handlers.append(
            ExceptionHandlerInfo(ExceptionHandlerType.EXCEPT, 10, 20)
        )
        assert analyzer.is_line_in_handler(15) is True
        assert analyzer.is_line_in_handler(5) is False

    def test_get_handler_at(self) -> None:
        """Test get_handler_at behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        info = ExceptionHandlerInfo(ExceptionHandlerType.EXCEPT, 10, 20)
        analyzer.get_state().all_handlers.append(info)
        assert analyzer.get_handler_at(15) is info
        assert analyzer.get_handler_at(5) is None

    def test_get_state(self) -> None:
        """Test get_state behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        assert isinstance(analyzer.get_state(), ExceptionHandlerState)

    def test_set_state(self) -> None:
        """Test set_state behavior."""
        analyzer = ExceptionHandlerAnalyzer()
        state = ExceptionHandlerState()
        analyzer.set_state(state)
        assert analyzer.get_state() is state


def test_should_skip_issue_in_handler() -> None:
    """Test should_skip_issue_in_handler behavior."""
    handlers = [ExceptionHandlerInfo(ExceptionHandlerType.EXCEPT, 10, 20)]
    assert should_skip_issue_in_handler(15, "UNREACHABLE_CODE", handlers) is True
    assert should_skip_issue_in_handler(5, "UNREACHABLE_CODE", handlers) is False
    assert should_skip_issue_in_handler(15, "OTHER_ISSUE", handlers) is False
    assert should_skip_issue_in_handler(None, "UNREACHABLE_CODE", handlers) is False
