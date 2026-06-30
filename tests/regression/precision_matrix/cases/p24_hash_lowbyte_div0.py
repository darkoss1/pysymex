# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(s: str) -> int:
    """
    post: True
    """
    if len(s) == 2:
        h = ((ord(s[0]) * 131) ^ ord(s[1])) & 255
        if h == 0x19 and s == "AZ":
            return 1 // (ord(s[0]) - 65)
    return 1
