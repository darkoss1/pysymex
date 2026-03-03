"""Example of contract-based verification in pysymex."""

from pysymex.analysis.contracts import requires, ensures


@requires(lambda x: x > 0)  # type: ignore[reportArgumentType]
@ensures(lambda result: result > 0)  # type: ignore[reportArgumentType]
def positive_doubler(x: int) -> int:
    """Doubles a positive number."""
    return x * 2


@requires(lambda x: x > 10)  # type: ignore[reportArgumentType]
@ensures(lambda result: result > 20)  # type: ignore[reportArgumentType]
def broken_contract(x: int) -> int:
    """This function violates its contract."""
    # Bug: returns x instead of double x, so if x=11, result=11 which is not > 20
    return x
