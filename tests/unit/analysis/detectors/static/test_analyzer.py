"""Tests for pysymex/analysis/detectors/static/analyzer.py."""

from typing import Any
from unittest.mock import Mock, patch
import dis
from pysymex.analysis.detectors.static.analyzer import DetectorRegistry, StaticAnalyzer


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestDetectorRegistry:
    """Test suite for pysymex.analysis.detectors.static.DetectorRegistry."""

    def test_register(self) -> None:
        """Test register behavior."""
        from pysymex.analysis.detectors.static.dead_code import DeadCodeDetector

        r = DetectorRegistry()
        d = DeadCodeDetector()
        r.register(d)
        assert d in r.detectors

    def test_get_all(self) -> None:
        """Test get_all behavior."""
        r = DetectorRegistry()
        all_d = r.get_all()
        assert len(all_d) > 0


class TestStaticAnalyzer:
    """Test suite for pysymex.analysis.detectors.static.StaticAnalyzer."""

    @patch("pysymex.analysis.detectors.static.analyzer._cached_get_instructions")
    @patch("pysymex.analysis.detectors.static.analyzer.PatternAnalyzer.analyze_function")
    def test_analyze_function(self, mock_analyze_func: Any, mock_get_instr: Any) -> None:
        """Test analyze_function behavior."""
        analyzer = StaticAnalyzer()
        mock_get_instr.return_value = [MockInstr("BINARY_OP", argrepr="/")]
        mock_analyze_func.return_value = Mock()
        code = Mock(co_name="f", co_firstlineno=1)
        issues = analyzer.analyze_function(code)
        assert isinstance(issues, list)
