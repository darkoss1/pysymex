# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x % 2 == 0 and x % 2 == 1:
        return 1 // 0
    return 1
