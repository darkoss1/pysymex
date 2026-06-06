import pysymex.core.identity.addressing


def test_next_address() -> None:
    """Test suite for pysymex.core.identity.addressing.next_address."""
    first = pysymex.core.identity.addressing.next_address()
    second = pysymex.core.identity.addressing.next_address()
    assert second == first + 1


def test_next_address_returns_unique_values() -> None:
    """Repeated address allocation returns unique monotonically increasing values."""
    addresses = {pysymex.core.identity.addressing.next_address() for _ in range(8)}
    assert len(addresses) == 8
