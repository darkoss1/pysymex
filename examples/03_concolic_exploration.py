"""
03: Concolic Path Exploration

This example demonstrates how pysymex uses the Z3 SMT solver to find highly specific
inputs that trigger deeply nested branch conditions—paths that traditional fuzzers
or random testing would take an extremely long time to discover.

To scan this example:
    pysymex scan examples/03_concolic_exploration.py
"""


def find_hidden_bug(secret_key: int) -> int:
    """
    A function with highly specific mathematical and logical branch conditions.
    pysymex will solve the constraints to find that when secret_key is 102 or 104,
    it triggers the RuntimeError.
    """
    if secret_key > 100:
        if secret_key < 105:
            if secret_key % 2 == 0:
                # Specific constraint: secret_key must be in {102, 104}
                raise RuntimeError("Hidden bug found via constraint solving!")
    return secret_key
