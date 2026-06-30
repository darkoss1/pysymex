# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    try:
        if x == 11:
            raise ValueError("boom")
    except ValueError:
        return 1
    return 1
