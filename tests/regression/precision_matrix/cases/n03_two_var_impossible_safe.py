# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int, y: int) -> int:
    """
    post: True
    """
    if 3 * x + 2 * y == 31 and x - y == 2 and x == 100:
        return 1 // 0
    return 1
