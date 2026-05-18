from __future__ import annotations

from pysymex.contracts import ensures, requires


@requires("x > 0")
@ensures("__result__ > 0")
def safe_positive_identity(x: int) -> int:
    return x


@ensures("__result__ > 0")
def violates_postcondition(x: int) -> int:
    return x


def unsupported_postcondition(__result__: int) -> object:
    _ = __result__
    return object()


@ensures(unsupported_postcondition)  # type: ignore[arg-type]  # intentionally unsupported
def unknown_postcondition() -> int:
    return 1
