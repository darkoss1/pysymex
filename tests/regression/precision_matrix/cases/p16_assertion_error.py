# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x * 2 == 22:
        assert False, "boom"
    return 1
