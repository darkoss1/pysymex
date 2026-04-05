from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Concatenate, ParamSpec, Protocol, TypeVar

_K = TypeVar("_K")
_P = ParamSpec("_P")
_R = TypeVar("_R")
_T = TypeVar("_T")
_T_co = TypeVar("_T_co", covariant=True)
_U = TypeVar("_U")
_V = TypeVar("_V")


class SearchStrategy(Protocol[_T_co]):
    def map(self, pack: Callable[[_T_co], _U]) -> SearchStrategy[_U]: ...
    def filter(self, predicate: Callable[[_T_co], bool]) -> SearchStrategy[_T_co]: ...
    def flatmap(
        self,
        expand: Callable[[_T_co], SearchStrategy[_U]],
    ) -> SearchStrategy[_U]: ...


class DrawFn(Protocol):
    def __call__(self, strategy: SearchStrategy[_T]) -> _T: ...


def integers(min_value: int | None = ..., max_value: int | None = ...) -> SearchStrategy[int]: ...
def booleans() -> SearchStrategy[bool]: ...
def text(
    alphabet: str | Sequence[str] | None = ...,
    min_size: int = ...,
    max_size: int | None = ...,
) -> SearchStrategy[str]: ...
def floats(
    *,
    min_value: float | None = ...,
    max_value: float | None = ...,
    allow_nan: bool = ...,
    allow_infinity: bool = ...,
) -> SearchStrategy[float]: ...
def none() -> SearchStrategy[None]: ...
def just(value: _T) -> SearchStrategy[_T]: ...
def sampled_from(elements: Sequence[_T]) -> SearchStrategy[_T]: ...
def one_of(*strategies: SearchStrategy[_T]) -> SearchStrategy[_T]: ...
def lists(
    elements: SearchStrategy[_T],
    min_size: int = ...,
    max_size: int | None = ...,
) -> SearchStrategy[list[_T]]: ...
def tuples(*elements: SearchStrategy[object]) -> SearchStrategy[tuple[object, ...]]: ...
def dictionaries(
    keys: SearchStrategy[_K],
    values: SearchStrategy[_V],
    min_size: int = ...,
    max_size: int | None = ...,
) -> SearchStrategy[dict[_K, _V]]: ...
def frozensets(
    elements: SearchStrategy[_T],
    min_size: int = ...,
    max_size: int | None = ...,
) -> SearchStrategy[frozenset[_T]]: ...


def composite(
    function: Callable[Concatenate[DrawFn, _P], _R],
) -> Callable[_P, SearchStrategy[_R]]: ...
