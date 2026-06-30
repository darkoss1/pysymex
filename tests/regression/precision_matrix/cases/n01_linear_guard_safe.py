# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(x: int) -> int:
    """
    post: True
    """
    if x == 1337:
        return 10 // ((x - 1337) + 1)
    return 1
