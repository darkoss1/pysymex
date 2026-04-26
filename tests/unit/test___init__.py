import pytest
import pysymex
from unittest.mock import patch


def test_getattr_available() -> None:
    """Test __getattr__ returns correct value for available property."""
    val = getattr(pysymex, "Z3_AVAILABLE")
    assert isinstance(val, bool)


def test_getattr_missing() -> None:
    """Test __getattr__ raises AttributeError for missing export."""
    with pytest.raises(AttributeError, match="has no attribute"):
        getattr(pysymex, "NON_EXISTENT_ATTRIBUTE")


def test_getattr_z3_import_error() -> None:
    """Test __getattr__ raises RuntimeError when Z3 fails and target requires Z3."""
    # We must patch _Z3_IMPORT_ERROR inside pysymex
    with patch("pysymex._Z3_IMPORT_ERROR", RuntimeError("mock err")):
        with pytest.raises(RuntimeError, match="mock err"):
            getattr(pysymex, "Z3Engine")


def test_getattr_z3_import_error_bypass() -> None:
    """Test __getattr__ bypasses RuntimeError for non-Z3 exports."""
    with patch("pysymex._Z3_IMPORT_ERROR", RuntimeError("mock err")):
        val = getattr(pysymex, "LogLevel")
        # should not raise
        assert val is not None


def test_dir() -> None:
    """Test __dir__ includes exports."""
    exports = dir(pysymex)
    assert "Z3_AVAILABLE" in exports
    assert "analyze" in exports
    assert "LogLevel" in exports
