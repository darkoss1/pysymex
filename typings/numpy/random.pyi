from __future__ import annotations

from typing import TypeVar, overload

from . import dtype, float32, int32, int64
from .typing import NDArray

_ScalarT = TypeVar("_ScalarT")


class Generator:
    def beta(
        self,
        a: float | NDArray[object],
        b: float | NDArray[object],
        size: int | tuple[int, ...] | None = ...,
    ) -> NDArray[float32]: ...

    @overload
    def integers(
        self,
        high: int,
        size: None = ...,
        dtype: type[int32] | type[int64] | dtype[_ScalarT] = ...,
    ) -> int: ...
    @overload
    def integers(
        self,
        high: int,
        size: int | tuple[int, ...],
        dtype: type[int32] | type[int64] | dtype[_ScalarT] = ...,
    ) -> NDArray[int64]: ...


def default_rng(seed: int | None = ...) -> Generator: ...
