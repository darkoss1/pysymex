# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


class Box:
    missing: int


def f(x: int) -> int:
    """
    post: True
    """
    b = Box()
    if x == 3:
        return b.missing
    return 1
