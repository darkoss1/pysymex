from __future__ import annotations

from pysymex.contracts import ensures, requires


@requires("x > 0")
@ensures("__result__ > 0")
def safe_positive_identity(x: int) -> int:
    return x


@ensures("__result__ > 0")
def violates_postcondition(x: int) -> int:
    return x


def unsupported_postcondition(__result__: int) -> bool:
    _ = __result__
    return object()  # type: ignore


@ensures(unsupported_postcondition)
def unknown_postcondition() -> int:
    return 1


def no_contracts_function(x: int) -> int:
    return x
