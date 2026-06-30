# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if ((x << 1) & 31) == 12:
        return 1 // (((x << 1) & 31) - 12)
    return 1
