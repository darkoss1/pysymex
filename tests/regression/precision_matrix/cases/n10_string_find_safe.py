# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(s: str) -> int:
    """
    post: True
    """
    pos = s.find("needle")
    if pos == 2:
        return 1 // (pos - 1)
    return 1
