import pysymex.core.types.havoc


class TestHavocValue:
    """Test suite for pysymex.core.types.havoc.HavocValue."""

    def test_havoc(self) -> None:
        """Scenario: havoc factory call; expected HavocValue instance result."""
        value, _constraint = pysymex.core.types.havoc.HavocValue.havoc("h0")
        assert isinstance(value, pysymex.core.types.havoc.HavocValue)


def test_is_havoc() -> None:
    """Scenario: check helper on havoc value; expected true."""
    value, _constraint = pysymex.core.types.havoc.HavocValue.havoc("h1")
    assert pysymex.core.types.havoc.is_havoc(value) is True


def test_has_havoc() -> None:
    """Scenario: mixed values include havoc; expected positive detection."""
    value, _constraint = pysymex.core.types.havoc.HavocValue.havoc("h2")
    assert pysymex.core.types.havoc.has_havoc(1, value) is True
