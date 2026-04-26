import pysymex.core.memory.addressing


def test_next_address() -> None:
    """Scenario: sequential allocation; expected strictly increasing addresses."""
    pysymex.core.memory.addressing.reset(1234)
    first = pysymex.core.memory.addressing.next_address()
    second = pysymex.core.memory.addressing.next_address()
    assert (first, second) == (1234, 1235)


def test_reset() -> None:
    """Scenario: reset to custom start; expected next value equals new start."""
    pysymex.core.memory.addressing.reset(77)
    assert pysymex.core.memory.addressing.next_address() == 77
