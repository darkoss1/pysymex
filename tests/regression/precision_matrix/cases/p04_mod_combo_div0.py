# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int, y: int) -> int:
    """
    post: True
    """
    if x % 7 == 3 and y % 5 == 4 and x + y == 19:
        return 1 // (x - 10)
    return 1
