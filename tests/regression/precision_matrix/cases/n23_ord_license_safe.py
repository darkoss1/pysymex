# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(s: str) -> int:
    """
    post: True
    """
    if len(s) == 4 and ord(s[0]) + 2 * ord(s[1]) + 3 * ord(s[2]) + 4 * ord(s[3]) == 670:
        if s[0] == "A" and s[1] == "B" and s[2] == "C" and s[3] == "D":
            return 1 // (ord(s[0]) - 64)
    return 1
