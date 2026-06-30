# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(s: str) -> int:
    """
    post: True
    """
    if len(s) == 4 and s[:2] == "AZ" and ord(s[2]) == 57:
        return 1 // (ord(s[2]) - 56)
    return 1
