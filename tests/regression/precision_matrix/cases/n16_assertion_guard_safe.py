# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x * 2 == 22 and x != 11:
        assert False, "unreachable"
    return 1
