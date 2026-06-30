# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(s: str) -> int:
    """
    post: True
    """
    if len(s) == 3 and s.count("x") == 3:
        return 1 // (len(s.replace("x", "")))
    return 1
