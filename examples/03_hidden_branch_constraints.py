"""
03: Hidden branch constraints

This example shows nested conditions that are hard to hit with random testing.
pysymex scan uses symbolic execution and the solver to find feasible inputs.

To scan this example:
    pysymex scan examples/03_hidden_branch_constraints.py
"""


def find_hidden_bug(secret_key: int) -> int:
    """
    A function with specific mathematical and logical branch conditions.
    A scan should find that secret_key in {102, 104} triggers the RuntimeError.
    """
    if secret_key > 100:
        if secret_key < 105:
            if secret_key % 2 == 0:
                raise RuntimeError("Hidden bug found via constraint solving!")
    return secret_key
