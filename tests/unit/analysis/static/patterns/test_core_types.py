from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment

from .pattern_fixtures import DummyHandler


class TestPatternKind:
    """Test suite for pysymex.analysis.static.patterns.kinds.PatternKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert PatternKind.DICT_GET.name == "DICT_GET"


class TestPatternMatch:
    """Test suite for pysymex.analysis.static.patterns.kinds.PatternMatch."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        match = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert match.kind == PatternKind.DICT_GET
        assert match.confidence == 0.9


class TestPatternHandler:
    """Test suite for pysymex.analysis.static.patterns.base.PatternHandler."""

    def test_pattern_kinds(self) -> None:
        """Test pattern_kinds behavior."""
        handler = DummyHandler()
        assert PatternKind.DICT_GET in handler.pattern_kinds()

    def test_match(self) -> None:
        """Test match behavior."""
        handler = DummyHandler()
        assert handler.match([], 0, TypeEnvironment()) is None

    def test_can_raise_error(self) -> None:
        """Test can_raise_error behavior."""
        handler = DummyHandler()
        match = PatternMatch(PatternKind.DICT_GET, 0.9, 10, 20)
        assert handler.can_raise_error(match, "Error") is True
