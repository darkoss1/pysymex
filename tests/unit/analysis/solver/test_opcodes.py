import pytest
from pysymex.analysis.solver.opcodes import OpcodeHandlersMixin
from pysymex.analysis.solver.analyzer import FunctionAnalyzer
from unittest.mock import Mock

class TestOpcodeHandlersMixin:
    """Test suite for pysymex.analysis.solver.opcodes.OpcodeHandlersMixin."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        engine = Mock()
        analyzer = FunctionAnalyzer(engine)
        assert hasattr(analyzer, "_op_LOAD_CONST")
