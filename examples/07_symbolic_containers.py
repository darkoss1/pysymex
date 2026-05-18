"""
07: Symbolic Container Models

This example demonstrates how pysymex models advanced Python container types
like lists, sets, and dictionaries, allowing it to mathematically reason about
mutations, lookups, and insertions in symbolic data structures.

To scan this example:
    pysymex scan examples/07_symbolic_containers.py
"""


def list_mutation_bug(value: int) -> int:
    """
    Appends elements to a list and triggers an error on specific item checks.
    pysymex tracks list structures to prove exactly when the bug is reachable.
    """
    items = []
    items.append(10)
    items.append(value)
    items.append(30)

    # If the middle element matches 99, trigger a bug
    if items[1] == 99:
        raise ValueError("Target value reached!")
    return items[1]


def set_deduplication_bug(x: int, y: int) -> int:
    """
    Uses Python sets to deduplicate elements. pysymex reasons about set
    membership and uniqueness to find the bug path.
    """
    unique_numbers = {x, y}

    # If both inputs are unique and non-zero, but their sum equals 100
    if len(unique_numbers) == 2:
        if x + y == 100:
            if x == 50:
                # Mathematically impossible: if x == 50 and x + y == 100,
                # then y must be 50. But if y == 50, then len({x, y}) would be 1!
                # Z3 SMT solver will prove this path is INFEASIBLE (0 false positives).
                raise RuntimeError("This line is unreachable!")

            if x == 40:
                # Feasible path: x=40, y=60. len({40, 60}) is 2.
                raise ValueError("Feasible bug triggered!")

    return len(unique_numbers)
