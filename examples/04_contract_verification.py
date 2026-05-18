"""
04: Contract-Based Verification

This example demonstrates pysymex's support for design-by-contract verification
using preconditions (@requires) and postconditions (@ensures). Preconditions define
what input constraints the caller must satisfy, and postconditions guarantee the properties
of the returned result.

To scan this example:
    pysymex scan examples/04_contract_verification.py
"""

from pysymex.contracts import ensures, requires


@requires(lambda value: value > 0)  # Precondition: input must be strictly positive
@ensures(lambda result: result > 0)  # Postcondition: output must be strictly positive
def positive_doubler(value: int) -> int:
    """
    A simple, safe function that fully satisfies both its precondition and postcondition.
    """
    return value * 2


@requires(lambda value: value > 10)  # Precondition: input must be > 10
@ensures(lambda result: result > 20)  # Postcondition: output must be > 20
def broken_contract_demo(value: int) -> int:
    """
    This function satisfies its contract under all valid preconditions by doubling the input.
    """
    return value * 2
