# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(xs: list[int]) -> int:
    """
    post: True
    """
    if len(xs) == 3 and xs[0] == 7:
        return xs[2]
    return 1
