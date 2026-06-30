# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x == 1:
        return next(1 // (x - 1) for _ in [0])
    return 1
