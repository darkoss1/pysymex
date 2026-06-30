"""
04: Contract-Based Verification

This example demonstrates pysymex's support for design-by-contract verification
using preconditions (@requires) and postconditions (@ensures). Preconditions define
what input constraints the caller must satisfy, and postconditions guarantee the properties
of the returned result.

To verify this example:
    pysymex contracts examples/04_contract_verification.py
"""

from pysymex.contracts import ensures, requires


@requires("value > 0")  # Precondition: input must be strictly positive
@ensures("result() > 0")  # Postcondition: output must be strictly positive
def positive_doubler(value: int) -> int:
    """
    A simple, safe function that fully satisfies both its precondition and postcondition.
    """
    return value * 2


@requires("value > 10")  # Precondition: input must be > 10
@ensures("result() > 20")  # Postcondition: output must be > 20
def bounded_doubler(value: int) -> int:
    """
    This function satisfies a stronger precondition/postcondition pair by doubling the input.
    """
    return value * 2
