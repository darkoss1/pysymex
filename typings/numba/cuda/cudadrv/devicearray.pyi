"""Type stubs for numba.cuda.cudadrv.devicearray module."""

from __future__ import annotations

from typing import Generic, Literal, TypeVar, overload

import numpy as np
import numpy.typing as npt

_ScalarType = TypeVar("_ScalarType", bound=np.generic)
_ScalarType2 = TypeVar("_ScalarType2", bound=np.generic)
_Numeric = int | float | complex | np.generic

class DeviceNDArray(Generic[_ScalarType]):
    """Device-resident array for CUDA computations."""

    @property
    def shape(self) -> tuple[int, ...]: ...

    @property
    def strides(self) -> tuple[int, ...]: ...

    @property
    def ndim(self) -> int: ...

    @property
    def size(self) -> int: ...

    @property
    def dtype(self) -> np.dtype[_ScalarType]: ...

    @property
    def nbytes(self) -> int: ...

    @property
    def device_ctypes_pointer(self) -> int: ...

    @property
    def gpu_data(self) -> int: ...

    @property
    def alloc_size(self) -> int: ...

    @property
    def is_c_contiguous(self) -> bool: ...

    @property
    def is_f_contiguous(self) -> bool: ...

    def copy_to_host(
        self,
        ary: npt.NDArray[_ScalarType] | None = None,
        stream: int | object = 0,
    ) -> npt.NDArray[_ScalarType]: ...

    def copy_to_device(
        self,
        ary: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType],
        stream: int | object = 0,
    ) -> None: ...

    @overload
    def __getitem__(self, idx: int) -> _ScalarType: ...
    @overload
    def __getitem__(self, idx: slice) -> DeviceNDArray[_ScalarType]: ...
    @overload
    def __getitem__(self, idx: tuple[int | slice, ...]) -> DeviceNDArray[_ScalarType] | _ScalarType: ...

    def __setitem__(self, idx: int | slice | tuple[int | slice, ...], val: _Numeric | npt.NDArray[_ScalarType]) -> None: ...

    def __len__(self) -> int: ...

    def reshape(
        self,
        *newshape: int | tuple[int, ...],
        order: Literal["C", "F", "A"] = "C",
    ) -> DeviceNDArray[_ScalarType]: ...

    def ravel(self, order: Literal["C", "F", "A"] = "C") -> DeviceNDArray[_ScalarType]: ...

    def view(self, dtype: np.dtype[_ScalarType2]) -> DeviceNDArray[_ScalarType2]: ...

    def split(self, section: int, stream: int | object = 0) -> list[DeviceNDArray[_ScalarType]]: ...
