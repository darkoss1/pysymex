# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if 0 <= x < 16 and x.bit_count() == 0:
        return 1 // x
    return 1
