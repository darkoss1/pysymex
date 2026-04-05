from __future__ import annotations

from collections.abc import Callable
from typing import ParamSpec, TypeAlias, TypeVar, overload

_P = ParamSpec("_P")
_R = TypeVar("_R")

_Predicate1: TypeAlias = Callable[[object], bool]
_Predicate2: TypeAlias = Callable[[object, object], bool]
_Predicate3: TypeAlias = Callable[[object, object, object], bool]
_Predicate4: TypeAlias = Callable[[object, object, object, object], bool]
Predicate: TypeAlias = _Predicate1 | _Predicate2 | _Predicate3 | _Predicate4


class ViolationError(Exception): ...


@overload
def require(
    condition: Predicate,
    description: str | None = ...,
    enabled: bool = ...,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
@overload
def require(
    condition: Callable[..., bool],
    description: str | None = ...,
    enabled: bool = ...,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...


@overload
def ensure(
    condition: Predicate,
    description: str | None = ...,
    enabled: bool = ...,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
@overload
def ensure(
    condition: Callable[..., bool],
    description: str | None = ...,
    enabled: bool = ...,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
