# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if (x & 3) == 4:
        return 1 // 0
    return 1
