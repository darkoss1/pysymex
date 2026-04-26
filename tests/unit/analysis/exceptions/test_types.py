import pytest
from pysymex.analysis.exceptions.types import (
    ExceptionWarningKind,
    HandlerIntent,
    ExceptionWarning,
    ExceptionHandler,
    TryBlock,
)


class TestExceptionWarningKind:
    """Test suite for pysymex.analysis.exceptions.types.ExceptionWarningKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ExceptionWarningKind.UNCAUGHT_EXCEPTION.name == "UNCAUGHT_EXCEPTION"


class TestHandlerIntent:
    """Test suite for pysymex.analysis.exceptions.types.HandlerIntent."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert HandlerIntent.SAFETY_NET.name == "SAFETY_NET"
        assert HandlerIntent.SILENCED.name == "SILENCED"


class TestExceptionWarning:
    """Test suite for pysymex.analysis.exceptions.types.ExceptionWarning."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        w = ExceptionWarning(
            kind=ExceptionWarningKind.UNCAUGHT_EXCEPTION, file="test.py", line=10, message="msg"
        )
        assert w.kind == ExceptionWarningKind.UNCAUGHT_EXCEPTION
        assert w.file == "test.py"
        assert w.line == 10
        assert w.message == "msg"


class TestExceptionHandler:
    """Test suite for pysymex.analysis.exceptions.types.ExceptionHandler."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        h = ExceptionHandler(line=15, exception_types=["ValueError"])
        assert h.line == 15
        assert "ValueError" in h.exception_types
        assert h.is_bare is False


class TestTryBlock:
    """Test suite for pysymex.analysis.exceptions.types.TryBlock."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        tb = TryBlock(start_line=10, end_line=20)
        assert tb.start_line == 10
        assert tb.end_line == 20
        assert len(tb.handlers) == 0
