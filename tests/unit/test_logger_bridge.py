import logging
from io import StringIO

from pysymex._internal.logging.bridge import PythonLoggingBridge, setup_python_logging
from pysymex._internal.logging.categories import LogCategory
from pysymex._internal.logging.logger import PysymexLogger
from pysymex._internal.logging.root import reset_logging


class TestPythonLoggingBridge:
    """Test suite for pysymex._internal.logging.PythonLoggingBridge."""

    def test_emit_error(self) -> None:
        """Test emit behavior for errors."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.ERROR, "", 0, "err", (), None)
        bridge.emit(record)
        assert "[ERR] [test] err" in stream.getvalue()

    def test_emit_warning(self) -> None:
        """Test emit behavior for warnings."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.WARNING, "", 0, "warn", (), None)
        bridge.emit(record)
        assert "[WARN] [test] warn" in stream.getvalue()

    def test_emit_info(self) -> None:
        """Test emit behavior for info."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord("test", logging.INFO, "", 0, "info", (), None)
        bridge.emit(record)
        assert "info" in stream.getvalue()

    def test_emit_preserves_source_logger_name(self) -> None:
        """Bridge output should show the original stdlib logger name."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord(
            "pysymex._internal.execution",
            logging.INFO,
            "",
            0,
            "msg",
            (),
            None,
        )
        bridge.emit(record)
        assert "[pysymex._internal.execution] msg" in stream.getvalue()

    def test_bridge_warning_bypasses_category_filter(self) -> None:
        """Bridged warnings should remain visible even with focused categories."""
        stream = StringIO()
        target = PysymexLogger(
            stream=stream,
            color=False,
            categories={LogCategory.SOLVER},
            history_capacity=5,
        )
        bridge = PythonLoggingBridge(target)
        record = logging.LogRecord(
            "pysymex._internal.analysis.other", logging.WARNING, "", 0, "warn", (), None
        )
        bridge.emit(record)

        assert "[WARN] [pysymex._internal.analysis.other] warn" in stream.getvalue()
        assert [entry.message for entry in target.get_entries()] == ["warn"]

    def test_emit_preserves_exception_info(self) -> None:
        """Bridge should pass raw exception info to the pysymex sink."""
        stream = StringIO()
        target = PysymexLogger(stream=stream, color=False)
        bridge = PythonLoggingBridge(target)
        try:
            raise RuntimeError("bridge failure")
        except RuntimeError as exc:
            record = logging.LogRecord("pysymex.test", logging.ERROR, "", 0, "err", (), None)
            record.exc_info = (type(exc), exc, exc.__traceback__)
            bridge.emit(record)
        assert "RuntimeError: bridge failure" in stream.getvalue()


def test_setup_python_logging() -> None:
    """Test setup_python_logging behavior."""
    reset_logging()
    setup_python_logging()
    py_logger = logging.getLogger("pysymex")
    assert any(isinstance(h, PythonLoggingBridge) for h in py_logger.handlers)


def test_setup_python_logging_prevents_duplicate_handlers() -> None:
    """Repeated setup calls should not duplicate bridge handlers."""
    reset_logging()
    py_logger = logging.getLogger("pysymex")
    py_logger.handlers.clear()
    setup_python_logging()
    setup_python_logging()
    bridges = [h for h in py_logger.handlers if isinstance(h, PythonLoggingBridge)]
    assert len(bridges) == 1
