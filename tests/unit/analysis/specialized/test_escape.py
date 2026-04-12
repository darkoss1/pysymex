import pytest
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.escape import (
    EscapeState, EscapeInfo, EscapeAnalyzer
)

class TestEscapeState:
    """Test suite for pysymex.analysis.specialized.escape.EscapeState."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert EscapeState.NO_ESCAPE.name == "NO_ESCAPE"
        assert EscapeState.GLOBAL_ESCAPE.name == "GLOBAL_ESCAPE"

class TestEscapeInfo:
    """Test suite for pysymex.analysis.specialized.escape.EscapeInfo."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = EscapeInfo(EscapeState.NO_ESCAPE)
        assert info.state == EscapeState.NO_ESCAPE

class TestEscapeAnalyzer:
    """Test suite for pysymex.analysis.specialized.escape.EscapeAnalyzer."""
    @patch("pysymex.analysis.specialized.escape._cached_get_instructions")
    def test_analyze_function(self, mock_instrs) -> None:
        """Test analyze_function behavior."""
        mock_instrs.return_value = []
        analyzer = EscapeAnalyzer()
        res = analyzer.analyze_function(Mock(co_varnames=("a", "b"), co_argcount=2)) # type: ignore[arg-type]
        assert isinstance(res, dict)
