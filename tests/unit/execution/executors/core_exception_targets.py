"""Target programs for symbolic executor exception-semantics tests."""

from __future__ import annotations


def caught_zero_division(x: int) -> int:
    try:
        return 10 // x
    except ZeroDivisionError:
        return 0


def reraise_caught_zero_division(x: int) -> int:
    try:
        return 10 // x
    except ZeroDivisionError:
        raise


def outer_handler_catches_reraised_zero_division(x: int) -> int:
    try:
        try:
            return 10 // x
        except ZeroDivisionError:
            raise
    except ZeroDivisionError:
        return 7


def caught_zero_division_rebinds_before_assert(x: int) -> int:
    try:
        _ = 10 // x
    except ZeroDivisionError:
        x = 1
    assert x != 0
    return x


def wrong_handler_zero_division(x: int) -> int:
    try:
        return 10 // x
    except ValueError:
        return 0


def tuple_handler_zero_division(x: int) -> int:
    try:
        return 10 // x
    except (ZeroDivisionError, ValueError):
        return 0


def try_finally_zero_division_uncaught(x: int) -> int:
    value = 0
    try:
        value = 10 // x
    finally:
        value += 1
    return value


def try_finally_zero_division_guarded(x: int) -> int:
    value = 0
    try:
        if x != 0:
            value = 10 // x
    finally:
        value += 1
    return value


def bounded_while_post_loop_assertion(x: int) -> int:
    total = 0
    step = 0
    while step < 3:
        total += step
        step += 1
    if x == total:
        assert x != 3
    return total


def uncaught_runtime_error(flag: bool) -> int:
    if flag:
        raise RuntimeError("boom")
    return 0


def caught_runtime_error(flag: bool) -> int:
    try:
        if flag:
            raise RuntimeError("boom")
    except RuntimeError:
        return 1
    return 0


def _raise_value_error() -> int:
    raise ValueError("boom")


def caught_interprocedural_value_error() -> int:
    try:
        return _raise_value_error()
    except ValueError:
        return 7


def wrong_handler_interprocedural_value_error() -> int:
    try:
        return _raise_value_error()
    except TypeError:
        return 7


def _catch_own_value_error() -> int:
    try:
        raise ValueError("inner")
    except ValueError:
        return 7


def nested_callee_catches_own_value_error() -> int:
    return _catch_own_value_error()


def _divide_by_zero() -> int:
    return 10 // 0


def caught_interprocedural_division_continues_to_assertion() -> int:
    value = 0
    try:
        value = _divide_by_zero()
    except ZeroDivisionError:
        value = 1
    assert value == 0
    return value


class RaisingTruth:
    def __bool__(self) -> bool:
        raise ValueError("truth")


def caught_protocol_value_error() -> int:
    try:
        if RaisingTruth():
            return 0
    except ValueError:
        return 7
    return 1


def wrong_handler_protocol_value_error() -> int:
    try:
        if RaisingTruth():
            return 0
    except TypeError:
        return 7
    return 1


class DividingTruth:
    def __bool__(self) -> bool:
        return (10 // 0) == 1


def caught_protocol_division_continues_to_assertion() -> int:
    value = 0
    try:
        if DividingTruth():
            value = 2
    except ZeroDivisionError:
        value = 1
    assert value == 0
    return value


class SuppressingContext:
    def __enter__(self) -> int:
        return 1

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return True


class PropagatingContext:
    def __enter__(self) -> int:
        return 1

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False


class InternallyHandlingContext:
    def __enter__(self) -> int:
        return 1

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            _ = 10 // 0
        except ZeroDivisionError:
            return True
        return False


def suppressed_context_exception_continues_to_assertion() -> int:
    value = 0
    with SuppressingContext():
        value = 10 // 0
    assert value == 1
    return value


def propagated_context_exception_does_not_continue_to_assertion() -> int:
    value = 0
    with PropagatingContext():
        value = 10 // 0
    assert value == 1
    return value


def propagated_context_exception_reaches_outer_handler() -> int:
    value = 0
    try:
        with PropagatingContext():
            value = 10 // 0
    except ZeroDivisionError:
        value = 1
    assert value == 0
    return value


def internally_handled_context_exception_continues_to_assertion() -> int:
    value = 0
    with InternallyHandlingContext():
        value = 10 // 0
    assert value == 1
    return value
