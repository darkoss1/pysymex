# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(xs: tuple[int, int]) -> int:
    """
    post: True
    """
    if xs[0] + xs[1] == 9:
        return xs[2]  # pyright: ignore[reportGeneralTypeIssues]
    return 1
