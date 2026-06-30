# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if (x & 15) == 10:
        return 1 // ((x & 15) - 10)
    return 1
