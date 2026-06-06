from types import CodeType


def make_dummy_code() -> CodeType:
    def f() -> None:
        for _i in range(10):
            pass

    return f.__code__
