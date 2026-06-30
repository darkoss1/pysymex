# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x * x - 5 * x + 6 == 0:
        return 1 // (x - 2)
    return 1
