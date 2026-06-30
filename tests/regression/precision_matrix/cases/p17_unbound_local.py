# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(flag: bool) -> int:
    """
    post: True
    """
    if flag:
        y = 1
    return y  # pyright: ignore[reportPossiblyUnboundVariable]
