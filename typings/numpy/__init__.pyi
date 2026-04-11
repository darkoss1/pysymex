from __future__ import annotations

from collections.abc import Sequence
from typing import Generic, TypeVar, overload

from . import random, typing
from .typing import ArrayLike, NBitBase, NDArray

_ShapeT = TypeVar("_ShapeT")
_ScalarT = TypeVar("_ScalarT", covariant=True)
_ScalarS = TypeVar("_ScalarS")
_NBitT = TypeVar("_NBitT", bound=NBitBase)


class generic:
    ...


class integer(generic, Generic[_NBitT]):
    ...


class floating(generic, Generic[_NBitT]):
    ...


class complexfloating(generic, Generic[_NBitT]):
    ...


class bool_(int, integer[NBitBase]):
    ...


class int8(int, integer[NBitBase]):
    ...


class int16(int, integer[NBitBase]):
    ...


class int32(int, integer[NBitBase]):
    ...


class int64(int, integer[NBitBase]):
    ...


class intp(int, integer[NBitBase]):
    ...


class uint8(int, integer[NBitBase]):
    ...


class uint16(int, integer[NBitBase]):
    ...


class uint32(int, integer[NBitBase]):
    ...


class uint64(int, integer[NBitBase]):
    ...


class float32(float, floating[NBitBase]):
    ...


class float64(float, floating[NBitBase]):
    ...


class void(generic):
    @overload
    def __getitem__(self, index: int) -> int: ...
    @overload
    def __getitem__(self, index: str) -> int: ...


class dtype(Generic[_ScalarT]):
    @overload
    def __init__(self, dtype: type[_ScalarT]) -> None: ...
    @overload
    def __init__(self, dtype: "dtype[_ScalarT]") -> None: ...
    @overload
    def __init__(self, dtype: str) -> None: ...
    @overload
    def __init__(self, dtype: Sequence[tuple[str, type[generic]]], align: bool = ...) -> None: ...

    @property
    def itemsize(self) -> int: ...

    def __eq__(self, other: object) -> bool: ...
    def __ne__(self, other: object) -> bool: ...


class ndarray(Generic[_ShapeT, _ScalarT]):
    shape: _ShapeT
    ndim: int
    size: int
    dtype: dtype[_ScalarT]
    nbytes: int

    def __len__(self) -> int: ...
    @overload
    def __getitem__(self, index: int) -> _ScalarT: ...
    @overload
    def __getitem__(self, index: slice | tuple[object, ...]) -> ndarray[_ShapeT, _ScalarT]: ...
    def __setitem__(self, index: int | slice | tuple[object, ...], value: object) -> None: ...
    def astype(self, dtype: type[_ScalarS] | dtype[_ScalarS]) -> ndarray[_ShapeT, _ScalarS]: ...
    def copy(self) -> ndarray[_ShapeT, _ScalarT]: ...
    def __add__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __radd__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __sub__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __rsub__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __mul__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __rmul__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __truediv__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __rtruediv__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __and__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def __rand__(self, other: object) -> ndarray[_ShapeT, object]: ...
    def sum(self) -> object: ...


newaxis: None


@overload
def full(
    shape: int | tuple[int, ...],
    fill_value: int | float,
    dtype: type[_ScalarS] | dtype[_ScalarS],
) -> NDArray[_ScalarS]: ...
@overload
def full(
    shape: int | tuple[int, ...],
    fill_value: int | float,
    dtype: None = ...,
) -> NDArray[float64]: ...


@overload
def zeros(
    shape: int | tuple[int, ...],
    dtype: type[_ScalarS] | dtype[_ScalarS],
) -> NDArray[_ScalarS]: ...
@overload
def zeros(
    shape: int | tuple[int, ...],
    dtype: None = ...,
) -> NDArray[float64]: ...


@overload
def ones(
    shape: int | tuple[int, ...],
    dtype: type[_ScalarS] | dtype[_ScalarS],
) -> NDArray[_ScalarS]: ...
@overload
def ones(
    shape: int | tuple[int, ...],
    dtype: None = ...,
) -> NDArray[float64]: ...


def ascontiguousarray(
    a: ArrayLike | ndarray[tuple[int, ...], object],
    dtype: type[_ScalarS] | dtype[_ScalarS] | None = ...,
) -> NDArray[_ScalarS] | NDArray[object]: ...


@overload
def argmax(a: NDArray[object], axis: None = ...) -> int: ...
@overload
def argmax(a: NDArray[object], axis: int) -> NDArray[int32]: ...


def where(
    condition: NDArray[object],
    x: NDArray[object],
    y: NDArray[object],
) -> NDArray[object]: ...


def unpackbits(
    a: NDArray[uint8],
    axis: int | None = ...,
) -> NDArray[uint8]: ...


def median(
    a: NDArray[object] | Sequence[object],
    axis: int | None = ...,
) -> float64: ...


def std(
    a: NDArray[object] | Sequence[object],
    axis: int | None = ...,
) -> float64: ...


__all__ = [
    "ArrayLike",
    "NBitBase",
    "argmax",
    "ascontiguousarray",
    "dtype",
    "float32",
    "float64",
    "full",
    "generic",
    "int32",
    "int64",
    "int8",
    "int16",
    "intp",
    "median",
    "ndarray",
    "newaxis",
    "ones",
    "random",
    "std",
    "typing",
    "uint16",
    "uint32",
    "uint64",
    "uint8",
    "unpackbits",
    "void",
    "where",
    "zeros",
]

from typing import Any
array_equal: Any
testing: Any

