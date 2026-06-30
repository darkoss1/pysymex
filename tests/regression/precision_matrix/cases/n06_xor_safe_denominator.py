# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if (x ^ 0x55) == 0x42:
        return 1 // ((x - 0x17) + 1)
    return 1
