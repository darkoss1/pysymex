# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


class C:
    def __enter__(self) -> int:
        return 1

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


def f(x: int) -> int:
    """
    post: True
    """
    if x == 4:
        with C():
            return 1 // ((x - 4) + 1)
    return 1
