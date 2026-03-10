"""Example: Intentionally buggy functions for demonstrating pysymex.

Run pysymex on this file to see it detect the following bugs:
- Division by zero in div_zero()
- Index out of bounds in oob()
- None dereference in null_ref()

Usage:
    pysymex scan examples/buggy_code.py
"""


def div_zero(x):
    if x == 0:
        return 10 / x
    return x


def oob(x):
    lst = [1, 2, 3]
    if x > 5:
        return lst[x]
    return lst[0]


def null_ref(x):
    a = None
    if x > 10:
        return a.attribute  # type: ignore[reportAttributeAccessIssue]
    return x
