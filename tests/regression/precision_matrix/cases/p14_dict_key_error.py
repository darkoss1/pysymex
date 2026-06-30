# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(d: dict[str, int]) -> int:
    """
    post: True
    """
    if len(d) == 1 and "trigger" in d:
        return d["missing"]
    return 1
