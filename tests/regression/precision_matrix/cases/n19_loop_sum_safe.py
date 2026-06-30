# generated adversarial exception-safety benchmark
# Each function has post: True so CrossHair checks uncaught exceptions.


def f(n: int) -> int:
    """
    post: True
    """
    acc = 0
    if 0 <= n <= 6:
        for i in range(n):
            acc += i
        if n == 5 and acc == 10:
            return 1 // (acc - 9)
    return 1
