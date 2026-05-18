"""
01: Basic Safety Guards

This example demonstrates how pysymex can formally reason about standard arithmetic
and sequence operations to verify their safety, highlighting the difference
between unsafe and safely-guarded functions.

To scan this example:
    pysymex scan examples/01_basic_safety_guards.py
"""


def unsafe_division(numerator: int, denominator: int) -> int:
    """
    An unguarded division that will trigger a DIVISION_BY_ZERO issue
    when the symbolic engine identifies denominator == 0 is feasible.
    """
    return numerator // denominator


def safe_division(numerator: int, denominator: int) -> int:
    """
    A safely guarded division. pysymex will prove that the denominator
    cannot be zero in the active execution path, showing zero issues.
    """
    if denominator == 0:
        return 0
    return numerator // denominator


def unsafe_modulo(dividend: int, divisor: int) -> int:
    """
    Modulo operation that crashes if divisor is 0.
    """
    return dividend % divisor


def safe_modulo(dividend: int, divisor: int) -> int:
    """
    Modulo operation safely guarded against division/modulo by zero.
    """
    if divisor == 0:
        return 0
    return dividend % divisor


def unsafe_bitwise_shift(value: int, shift_amount: int) -> int:
    """
    Bitwise shift that crashes (raises ValueError) in Python if the
    shift amount is negative.
    """
    return value << shift_amount


def safe_bitwise_shift(value: int, shift_amount: int) -> int:
    """
    Safely guarded bitwise shift ensuring non-negative shift values.
    """
    if shift_amount < 0:
        return 0
    return value << shift_amount
