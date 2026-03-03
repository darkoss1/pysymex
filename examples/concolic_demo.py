"""Example of concolic execution in pysymex."""


def find_bug(x: int) -> int:
    """A function with a tricky conditional path."""
    if x > 100:
        if x < 105:
            if x % 2 == 0:
                # Tricky path: x in [102, 104]
                raise RuntimeError("Bug found!")
    return x
