# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(n: int) -> int:
    """
    post: True
    """
    if 0 <= n <= 4:
        k = n
        while k > 0:
            k -= 1
        if n == 4:
            return 1 // k
    return 1
