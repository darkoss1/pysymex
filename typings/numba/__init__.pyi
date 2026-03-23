"""Type stubs for Numba — JIT compilation for Python with CUDA support.

Numba provides just-in-time compilation for numerical Python code
and GPU kernels via CUDA. These stubs cover all Numba usage in pysymex.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from types import TracebackType
from typing import (
    Generic,
    Literal,
    ParamSpec,
    Protocol,
    TypeVar,
    overload,
    runtime_checkable,
)

import numpy as np
import numpy.typing as npt

# ── Type Variables ─────────────────────────────────────────────────

_T = TypeVar("_T")
_T_co = TypeVar("_T_co", covariant=True)
_P = ParamSpec("_P")
_F = TypeVar("_F", bound=Callable[..., object])
_ScalarType = TypeVar("_ScalarType", bound=np.generic)
_ScalarType2 = TypeVar("_ScalarType2", bound=np.generic)
_IntType = TypeVar("_IntType", bound=np.integer[np.typing.NBitBase])
_FloatType = TypeVar("_FloatType", bound=np.floating[np.typing.NBitBase])

# ── Type Aliases ───────────────────────────────────────────────────

_ShapeLike = int | tuple[int, ...]
_DTypeLike = type[_ScalarType] | np.dtype[_ScalarType] | str
_Numeric = int | float | complex | np.generic
_ArrayLike = _Numeric | Sequence[_Numeric] | npt.NDArray[np.generic]
_Signature = str | tuple[type[np.generic] | str, ...] | list[str | tuple[type[np.generic] | str, ...]]
_InlineOption = Literal["never", "always"] | Callable[[object, object], bool]

# ── Version info ───────────────────────────────────────────────────

__version__: str
version_info: tuple[int, int, int]

# ── Numba scalar types ─────────────────────────────────────────────

class NumbaType:
    """Base class for Numba types."""
    ...

class uint8(NumbaType):
    """8-bit unsigned integer type."""
    def __new__(cls, value: int = 0) -> np.uint8: ...

class uint16(NumbaType):
    """16-bit unsigned integer type."""
    def __new__(cls, value: int = 0) -> np.uint16: ...

class uint32(NumbaType):
    """32-bit unsigned integer type."""
    def __new__(cls, value: int = 0) -> np.uint32: ...

class uint64(NumbaType):
    """64-bit unsigned integer type."""
    def __new__(cls, value: int = 0) -> np.uint64: ...

class int8(NumbaType):
    """8-bit signed integer type."""
    def __new__(cls, value: int = 0) -> np.int8: ...

class int16(NumbaType):
    """16-bit signed integer type."""
    def __new__(cls, value: int = 0) -> np.int16: ...

class int32(NumbaType):
    """32-bit signed integer type."""
    def __new__(cls, value: int = 0) -> np.int32: ...

class int64(NumbaType):
    """64-bit signed integer type."""
    def __new__(cls, value: int = 0) -> np.int64: ...

class float32(NumbaType):
    """32-bit floating point type."""
    def __new__(cls, value: float = 0.0) -> np.float32: ...

class float64(NumbaType):
    """64-bit floating point type."""
    def __new__(cls, value: float = 0.0) -> np.float64: ...

class complex64(NumbaType):
    """64-bit complex type (2x float32)."""
    def __new__(cls, value: complex = 0j) -> np.complex64: ...

class complex128(NumbaType):
    """128-bit complex type (2x float64)."""
    def __new__(cls, value: complex = 0j) -> np.complex128: ...

class boolean(NumbaType):
    """Boolean type."""
    def __new__(cls, value: bool = False) -> np.bool_: ...

class void(NumbaType):
    """Void return type."""
    ...

# ── Type aliases ───────────────────────────────────────────────────

b1 = boolean
u1 = uint8
u2 = uint16
u4 = uint32
u8 = uint64
i1 = int8
i2 = int16
i4 = int32
i8 = int64
f4 = float32
f8 = float64
c8 = complex64
c16 = complex128

byte = int8
ubyte = uint8
short = int16
ushort = uint16
intc = int32
uintc = uint32
intp = int64
uintp = uint64
long_ = int64
ulong = uint64
longlong = int64
ulonglong = uint64
single = float32
double = float64
csingle = complex64
cdouble = complex128

# ── JIT decorators ─────────────────────────────────────────────────

@overload
def njit(func: _F) -> _F: ...
@overload
def njit(
    signature: _Signature = ...,
    *,
    parallel: bool = False,
    fastmath: bool | dict[str, bool] = False,
    cache: bool = False,
    boundscheck: bool = False,
    nogil: bool = False,
    error_model: Literal["python", "numpy"] = "python",
    forceobj: bool = False,
    locals: dict[str, NumbaType] = ...,
    pipeline_class: type[object] | None = None,
    inline: _InlineOption = "never",
    target: Literal["cpu"] = "cpu",
    debug: bool = False,
) -> Callable[[_F], _F]: ...

@overload
def jit(func: _F) -> _F: ...
@overload
def jit(
    signature: _Signature = ...,
    *,
    nopython: bool = False,
    parallel: bool = False,
    fastmath: bool | dict[str, bool] = False,
    cache: bool = False,
    boundscheck: bool = False,
    nogil: bool = False,
    forceobj: bool = False,
    looplift: bool = True,
    error_model: Literal["python", "numpy"] = "python",
    locals: dict[str, NumbaType] = ...,
    target: Literal["cpu"] = "cpu",
    debug: bool = False,
) -> Callable[[_F], _F]: ...

@overload
def vectorize(
    signatures: _Signature,
    *,
    target: Literal["cpu", "parallel", "cuda"] = "cpu",
    identity: _Numeric | None = None,
    nopython: bool = True,
    cache: bool = False,
    fastmath: bool = False,
) -> Callable[[_F], _F]: ...
@overload
def vectorize(
    func: _F,
    *,
    target: Literal["cpu", "parallel", "cuda"] = "cpu",
    identity: _Numeric | None = None,
    nopython: bool = True,
    cache: bool = False,
    fastmath: bool = False,
) -> _F: ...

@overload
def guvectorize(
    signatures: _Signature,
    layout: str,
    *,
    target: Literal["cpu", "parallel", "cuda"] = "cpu",
    nopython: bool = True,
    cache: bool = False,
    fastmath: bool = False,
    writable_args: tuple[int, ...] = (),
) -> Callable[[_F], _F]: ...
@overload
def guvectorize(
    func: _F,
    signatures: _Signature,
    layout: str,
    *,
    target: Literal["cpu", "parallel", "cuda"] = "cpu",
    nopython: bool = True,
    cache: bool = False,
    fastmath: bool = False,
    writable_args: tuple[int, ...] = (),
) -> _F: ...

@overload
def cfunc(
    signature: _Signature,
    *,
    nopython: bool = True,
    cache: bool = False,
    error_model: Literal["python", "numpy"] = "python",
    locals: dict[str, NumbaType] = ...,
) -> Callable[[_F], _F]: ...

@overload
def stencil(
    func: _F,
    *,
    neighborhood: tuple[tuple[int, int], ...] | None = None,
    standard_indexing: tuple[str, ...] = (),
    cval: float = 0.0,
) -> _F: ...
@overload
def stencil(
    *,
    neighborhood: tuple[tuple[int, int], ...] | None = None,
    standard_indexing: tuple[str, ...] = (),
    cval: float = 0.0,
) -> Callable[[_F], _F]: ...


# ── Parallel utilities ─────────────────────────────────────────────

def prange(start: int, stop: int | None = None, step: int = 1) -> range: ...
def set_parallel_chunksize(size: int) -> None: ...
def get_parallel_chunksize() -> int: ...
def get_num_threads() -> int: ...
def set_num_threads(n: int) -> None: ...


# ── Generated JIT functions ────────────────────────────────────────

@runtime_checkable
class JittedFunction(Protocol[_P, _T_co]):
    """Protocol for JIT-compiled functions."""

    def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> _T_co: ...

    @property
    def signatures(self) -> list[tuple[NumbaType, ...]]: ...

    @property
    def nopython_signatures(self) -> list[tuple[NumbaType, ...]]: ...

    def inspect_types(self, file: object = None) -> None: ...
    def inspect_llvm(self, signature: tuple[NumbaType, ...] | None = None) -> dict[str, str]: ...
    def inspect_asm(self, signature: tuple[NumbaType, ...] | None = None) -> dict[str, str]: ...
    def inspect_cfg(self, signature: tuple[NumbaType, ...] | None = None, show_wrapped: bool = False) -> object: ...
    def parallel_diagnostics(self, level: int = 1) -> str | None: ...
    def recompile(self) -> None: ...
    def disable_compile(self, val: bool = True) -> None: ...

    @property
    def stats(self) -> object: ...


# ── CUDA module ────────────────────────────────────────────────────

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
        stream: int | CUDAStream = 0,
    ) -> npt.NDArray[_ScalarType]: ...

    def copy_to_device(
        self,
        ary: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType],
        stream: int | CUDAStream = 0,
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

    def split(self, section: int, stream: int | CUDAStream = 0) -> list[DeviceNDArray[_ScalarType]]: ...


class CUDAStream:
    """CUDA stream wrapper for asynchronous operations."""

    @property
    def handle(self) -> int: ...

    def synchronize(self) -> None: ...

    def auto_synchronize(self) -> _CUDAAutoSync: ...

    def __enter__(self) -> CUDAStream: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


class _CUDAAutoSync:
    """Context manager for automatic stream synchronization."""
    def __enter__(self) -> _CUDAAutoSync: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


class CUDAEvent:
    """CUDA event for timing and synchronization."""

    def record(self, stream: CUDAStream | None = None) -> None: ...
    def wait(self, stream: CUDAStream | None = None) -> None: ...
    def synchronize(self) -> None: ...
    def elapsed_time(self, end: CUDAEvent) -> float: ...
    def query(self) -> bool: ...


class CUDADispatcher:
    """Compiled CUDA kernel dispatcher."""

    def __call__(self, *args: _ArrayLike | DeviceNDArray[np.generic], **kwargs: _Numeric) -> None: ...

    def __getitem__(self, config: tuple[int, int] | tuple[int, int, CUDAStream] | tuple[int, int, CUDAStream, int]) -> Callable[..., None]: ...

    @property
    def extensions(self) -> list[object]: ...

    def specialize(self, *args: NumbaType) -> CUDADispatcher: ...

    def inspect_types(self, file: object = None) -> None: ...
    def inspect_llvm(self) -> dict[str, str]: ...
    def inspect_asm(self, cc: tuple[int, int] | None = None) -> dict[str, str]: ...
    def inspect_sass(self, cc: tuple[int, int] | None = None) -> dict[str, str]: ...

    @property
    def max_threads_per_block(self) -> int: ...

    @property
    def regs_per_thread(self) -> int: ...


class _CUDAModule:
    """CUDA module namespace with GPU functionality."""

    DeviceNDArray = DeviceNDArray

    # ── Device array creation ──────────────────────────────────────

    @staticmethod
    @overload
    def to_device(ary: npt.NDArray[_ScalarType], stream: int | CUDAStream = 0, copy: bool = True) -> DeviceNDArray[_ScalarType]: ...
    @staticmethod
    @overload
    def to_device(ary: Sequence[int], stream: int | CUDAStream = 0, copy: bool = True) -> DeviceNDArray[np.int64]: ...
    @staticmethod
    @overload
    def to_device(ary: Sequence[float], stream: int | CUDAStream = 0, copy: bool = True) -> DeviceNDArray[np.float64]: ...

    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.float64] | Literal["float64"] = ..., strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.float64]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.float32] | Literal["float32"], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.float32]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.int32] | Literal["int32"], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.int32]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.int64] | Literal["int64"], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.int64]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.uint32] | Literal["uint32"], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.uint32]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: type[np.uint64] | Literal["uint64"], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[np.uint64]: ...
    @staticmethod
    @overload
    def device_array(shape: _ShapeLike, dtype: np.dtype[_ScalarType], strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C", stream: int | CUDAStream = 0) -> DeviceNDArray[_ScalarType]: ...

    @staticmethod
    def device_array_like(ary: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], stream: int | CUDAStream = 0) -> DeviceNDArray[_ScalarType]: ...

    @staticmethod
    def pinned_array(shape: _ShapeLike, dtype: _DTypeLike[_ScalarType] = ..., strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C") -> npt.NDArray[_ScalarType]: ...

    @staticmethod
    def pinned_array_like(ary: npt.NDArray[_ScalarType]) -> npt.NDArray[_ScalarType]: ...

    @staticmethod
    def mapped_array(shape: _ShapeLike, dtype: _DTypeLike[_ScalarType] = ..., strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C") -> npt.NDArray[_ScalarType]: ...

    @staticmethod
    def managed_array(shape: _ShapeLike, dtype: _DTypeLike[_ScalarType] = ..., strides: tuple[int, ...] | None = None, order: Literal["C", "F"] = "C") -> npt.NDArray[_ScalarType]: ...

    # ── Kernel compilation ─────────────────────────────────────────

    @staticmethod
    @overload
    def jit(func: _F) -> CUDADispatcher: ...
    @staticmethod
    @overload
    def jit(
        signature: _Signature = ...,
        *,
        device: bool = False,
        inline: bool | Literal["always", "never"] = False,
        link: list[str] = ...,
        debug: bool = False,
        opt: bool = True,
        lineinfo: bool = False,
        cache: bool = False,
        fastmath: bool = False,
        max_registers: int | None = None,
    ) -> Callable[[_F], CUDADispatcher]: ...

    # ── Thread/block intrinsics ────────────────────────────────────

    @staticmethod
    @overload
    def grid(ndim: Literal[1]) -> int: ...
    @staticmethod
    @overload
    def grid(ndim: Literal[2]) -> tuple[int, int]: ...
    @staticmethod
    @overload
    def grid(ndim: Literal[3]) -> tuple[int, int, int]: ...
    @staticmethod
    @overload
    def grid(ndim: int) -> int | tuple[int, ...]: ...

    @staticmethod
    @overload
    def gridsize(ndim: Literal[1]) -> int: ...
    @staticmethod
    @overload
    def gridsize(ndim: Literal[2]) -> tuple[int, int]: ...
    @staticmethod
    @overload
    def gridsize(ndim: Literal[3]) -> tuple[int, int, int]: ...
    @staticmethod
    @overload
    def gridsize(ndim: int) -> int | tuple[int, ...]: ...

    # Thread/block indices
    @staticmethod
    def threadIdx() -> _Dim3: ...
    @staticmethod
    def blockIdx() -> _Dim3: ...
    @staticmethod
    def blockDim() -> _Dim3: ...
    @staticmethod
    def gridDim() -> _Dim3: ...

    @staticmethod
    def warpsize() -> int: ...
    @staticmethod
    def laneid() -> int: ...

    # ── Synchronization ────────────────────────────────────────────

    @staticmethod
    def syncthreads() -> None: ...
    @staticmethod
    def syncthreads_count(predicate: bool) -> int: ...
    @staticmethod
    def syncthreads_and(predicate: bool) -> bool: ...
    @staticmethod
    def syncthreads_or(predicate: bool) -> bool: ...
    @staticmethod
    def syncwarp(mask: int = 0xFFFFFFFF) -> None: ...
    @staticmethod
    def synchronize() -> None: ...

    # ── Warp-level primitives ──────────────────────────────────────

    @staticmethod
    def shfl_sync(mask: int, value: _Numeric, src_lane: int) -> _Numeric: ...
    @staticmethod
    def shfl_up_sync(mask: int, value: _Numeric, delta: int) -> _Numeric: ...
    @staticmethod
    def shfl_down_sync(mask: int, value: _Numeric, delta: int) -> _Numeric: ...
    @staticmethod
    def shfl_xor_sync(mask: int, value: _Numeric, lane_mask: int) -> _Numeric: ...
    @staticmethod
    def vote_sync(mask: int, predicate: bool) -> int: ...
    @staticmethod
    def all_sync(mask: int, predicate: bool) -> bool: ...
    @staticmethod
    def any_sync(mask: int, predicate: bool) -> bool: ...
    @staticmethod
    def ballot_sync(mask: int, predicate: bool) -> int: ...
    @staticmethod
    def match_any_sync(mask: int, value: int) -> int: ...
    @staticmethod
    def match_all_sync(mask: int, value: int) -> tuple[int, bool]: ...
    @staticmethod
    def activemask() -> int: ...
    @staticmethod
    def lanemask_lt() -> int: ...

    # ── Shared/local memory ────────────────────────────────────────

    class local:
        @staticmethod
        def array(shape: _ShapeLike, dtype: type[_ScalarType] | np.dtype[_ScalarType]) -> npt.NDArray[_ScalarType]: ...

    class shared:
        @staticmethod
        def array(shape: _ShapeLike, dtype: type[_ScalarType] | np.dtype[_ScalarType]) -> npt.NDArray[_ScalarType]: ...

    class const:
        @staticmethod
        def array_like(ary: npt.NDArray[_ScalarType]) -> npt.NDArray[_ScalarType]: ...

    # ── Atomic operations ──────────────────────────────────────────

    class atomic:
        @staticmethod
        def add(array: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], index: int | tuple[int, ...], value: _Numeric) -> _Numeric: ...
        @staticmethod
        def sub(array: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], index: int | tuple[int, ...], value: _Numeric) -> _Numeric: ...
        @staticmethod
        def max(array: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], index: int | tuple[int, ...], value: _Numeric) -> _Numeric: ...
        @staticmethod
        def min(array: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], index: int | tuple[int, ...], value: _Numeric) -> _Numeric: ...
        @staticmethod
        def and_(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], value: int) -> int: ...
        @staticmethod
        def or_(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], value: int) -> int: ...
        @staticmethod
        def xor(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], value: int) -> int: ...
        @staticmethod
        def inc(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], value: int) -> int: ...
        @staticmethod
        def dec(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], value: int) -> int: ...
        @staticmethod
        def exch(array: npt.NDArray[_ScalarType] | DeviceNDArray[_ScalarType], index: int | tuple[int, ...], value: _Numeric) -> _Numeric: ...
        @staticmethod
        def compare_and_swap(array: npt.NDArray[np.integer[np.typing.NBitBase]] | DeviceNDArray[np.integer[np.typing.NBitBase]], index: int | tuple[int, ...], old: int, val: int) -> int: ...

    # ── Stream and event management ────────────────────────────────

    @staticmethod
    def stream() -> CUDAStream: ...
    @staticmethod
    def default_stream() -> CUDAStream: ...
    @staticmethod
    def event(timing: bool = True) -> CUDAEvent: ...

    # ── Device queries ─────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool: ...
    @staticmethod
    def detect() -> bool: ...
    @staticmethod
    def select_device(device_id: int) -> None: ...
    @staticmethod
    def get_current_device() -> _CUDADevice: ...
    @staticmethod
    def list_devices() -> list[_CUDADevice]: ...
    @staticmethod
    def gpus() -> _GPUList: ...
    @staticmethod
    def close() -> None: ...

    # ── Memory management ──────────────────────────────────────────

    @staticmethod
    def defer_cleanup() -> _DeferCleanup: ...
    @staticmethod
    def profile_start() -> None: ...
    @staticmethod
    def profile_stop() -> None: ...

    # ── Math functions (device) ────────────────────────────────────

    @staticmethod
    def fma(a: float, b: float, c: float) -> float: ...
    @staticmethod
    def cbrt(x: float) -> float: ...
    @staticmethod
    def brev(x: int) -> int: ...
    @staticmethod
    def clz(x: int) -> int: ...
    @staticmethod
    def ffs(x: int) -> int: ...
    @staticmethod
    def popc(x: int) -> int: ...
    @staticmethod
    def selp(cond: bool, true_val: _T, false_val: _T) -> _T: ...


class _Dim3:
    """3D index/dimension tuple."""
    x: int
    y: int
    z: int


class _CUDADevice:
    """CUDA device handle."""
    id: int
    name: str
    compute_capability: tuple[int, int]

    @property
    def TOTAL_MEMORY(self) -> int: ...
    @property
    def FREE_MEMORY(self) -> int: ...
    @property
    def MAX_THREADS_PER_BLOCK(self) -> int: ...
    @property
    def MAX_SHARED_MEMORY_PER_BLOCK(self) -> int: ...
    @property
    def MULTIPROCESSOR_COUNT(self) -> int: ...
    @property
    def WARP_SIZE(self) -> int: ...

    def __enter__(self) -> _CUDADevice: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


class _GPUList:
    """List of available GPUs."""
    def __len__(self) -> int: ...
    def __getitem__(self, idx: int) -> _CUDADevice: ...
    def __iter__(self) -> _GPUList: ...
    def __next__(self) -> _CUDADevice: ...


class _DeferCleanup:
    """Context manager for deferred memory cleanup."""
    def __enter__(self) -> _DeferCleanup: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


# Create cuda module instance
cuda: _CUDAModule


# ── cuda.random module ─────────────────────────────────────────────

class _CUDARandomModule:
    """CUDA random number generation module."""

    @staticmethod
    def create_xoroshiro128p_states(
        n: int,
        seed: int | None = None,
        subsequence_start: int = 0,
        stream: int | CUDAStream = 0,
    ) -> DeviceNDArray[np.uint64]: ...

    @staticmethod
    def init_xoroshiro128p_states(
        states: DeviceNDArray[np.uint64],
        seed: int,
        subsequence_start: int = 0,
        stream: int | CUDAStream = 0,
    ) -> None: ...

    @staticmethod
    def xoroshiro128p_uniform_float32(states: DeviceNDArray[np.uint64], index: int) -> np.float32: ...

    @staticmethod
    def xoroshiro128p_uniform_float64(states: DeviceNDArray[np.uint64], index: int) -> np.float64: ...

    @staticmethod
    def xoroshiro128p_normal_float32(states: DeviceNDArray[np.uint64], index: int) -> np.float32: ...

    @staticmethod
    def xoroshiro128p_normal_float64(states: DeviceNDArray[np.uint64], index: int) -> np.float64: ...


# ── Types module ───────────────────────────────────────────────────

class _TypesModule:
    """Numba types for signatures."""

    void = void
    boolean = boolean
    uint8 = uint8
    uint16 = uint16
    uint32 = uint32
    uint64 = uint64
    int8 = int8
    int16 = int16
    int32 = int32
    int64 = int64
    float32 = float32
    float64 = float64
    complex64 = complex64
    complex128 = complex128

    b1 = boolean
    u1 = uint8
    u2 = uint16
    u4 = uint32
    u8 = uint64
    i1 = int8
    i2 = int16
    i4 = int32
    i8 = int64
    f4 = float32
    f8 = float64
    c8 = complex64
    c16 = complex128

    @staticmethod
    def Array(dtype: NumbaType, ndim: int, layout: Literal["C", "F", "A"] = "A") -> NumbaType: ...

    @staticmethod
    def UniTuple(dtype: NumbaType, count: int) -> NumbaType: ...

    @staticmethod
    def Tuple(types: tuple[NumbaType, ...]) -> NumbaType: ...

    @staticmethod
    def List(dtype: NumbaType, reflected: bool = False) -> NumbaType: ...

    @staticmethod
    def Set(dtype: NumbaType, reflected: bool = False) -> NumbaType: ...

    @staticmethod
    def Dict(key: NumbaType, value: NumbaType, reflected: bool = False) -> NumbaType: ...

    @staticmethod
    def Optional(dtype: NumbaType) -> NumbaType: ...

    @staticmethod
    def FunctionType(sig: NumbaType) -> NumbaType: ...


types: _TypesModule


# ── Config module ──────────────────────────────────────────────────

class _ConfigModule:
    """Numba configuration."""

    DISABLE_JIT: bool
    NUMBA_NUM_THREADS: int
    NUMBA_THREADING_LAYER: str
    NUMBA_OPT: int
    NUMBA_LOOP_VECTORIZE: bool
    NUMBA_ENABLE_AVX: bool
    NUMBA_CPU_NAME: str
    NUMBA_CPU_FEATURES: str
    NUMBA_DEBUGINFO: bool
    NUMBA_BOUNDSCHECK: bool


config: _ConfigModule


# ── Errors ─────────────────────────────────────────────────────────

class NumbaError(Exception):
    """Base class for Numba errors."""
    ...

class TypingError(NumbaError):
    """Error during type inference."""
    ...

class LoweringError(NumbaError):
    """Error during code lowering."""
    ...

class CompilerError(NumbaError):
    """Error during compilation."""
    ...

class UnsupportedError(NumbaError):
    """Feature not supported in nopython mode."""
    ...

class NumbaPendingDeprecationWarning(FutureWarning):
    """Pending deprecation warning."""
    ...

class NumbaDeprecationWarning(DeprecationWarning):
    """Deprecation warning."""
    ...

class NumbaPerformanceWarning(UserWarning):
    """Performance-related warning."""
    ...


# ── Typed containers ───────────────────────────────────────────────

class typed:
    """Typed container constructors."""

    class List(Generic[_T]):
        """Typed list for use in JIT functions."""

        def __init__(self, iterable: Sequence[_T] = ...) -> None: ...
        def append(self, item: _T) -> None: ...
        def extend(self, items: Sequence[_T]) -> None: ...
        def insert(self, index: int, item: _T) -> None: ...
        def pop(self, index: int = -1) -> _T: ...
        def clear(self) -> None: ...
        def copy(self) -> typed.List[_T]: ...
        def count(self, value: _T) -> int: ...
        def index(self, value: _T, start: int = 0, stop: int = ...) -> int: ...
        def remove(self, value: _T) -> None: ...
        def reverse(self) -> None: ...
        def sort(self, key: Callable[[_T], object] | None = None, reverse: bool = False) -> None: ...
        def __len__(self) -> int: ...
        @overload
        def __getitem__(self, index: int) -> _T: ...
        @overload
        def __getitem__(self, index: slice) -> typed.List[_T]: ...
        def __setitem__(self, index: int, value: _T) -> None: ...
        @overload
        def __delitem__(self, index: int) -> None: ...
        @overload
        def __delitem__(self, index: slice) -> None: ...
        def __contains__(self, item: _T) -> bool: ...
        def __iter__(self) -> typed.List[_T]: ...
        def __next__(self) -> _T: ...

        @staticmethod
        def empty_list(item_type: NumbaType) -> typed.List[object]: ...

    class Dict(Generic[_T]):
        """Typed dict for use in JIT functions."""

        _KT = TypeVar("_KT")
        _VT = TypeVar("_VT")

        def __init__(self) -> None: ...
        def keys(self) -> typed.Dict[_T]: ...
        def values(self) -> typed.Dict[_T]: ...
        def items(self) -> typed.Dict[_T]: ...
        def get(self, key: object, default: _T | None = None) -> _T | None: ...
        def pop(self, key: object, default: _T = ...) -> _T: ...
        def popitem(self) -> tuple[object, _T]: ...
        def setdefault(self, key: object, default: _T | None = None) -> _T | None: ...
        def clear(self) -> None: ...
        def copy(self) -> typed.Dict[_T]: ...
        def update(self, other: typed.Dict[_T] | dict[object, _T]) -> None: ...
        def __len__(self) -> int: ...
        def __getitem__(self, key: object) -> _T: ...
        def __setitem__(self, key: object, value: _T) -> None: ...
        def __delitem__(self, key: object) -> None: ...
        def __contains__(self, key: object) -> bool: ...
        def __iter__(self) -> typed.Dict[_T]: ...
        def __next__(self) -> object: ...

        @staticmethod
        def empty(key_type: NumbaType, value_type: NumbaType) -> typed.Dict[object]: ...


# ── Extending Numba ────────────────────────────────────────────────

def typeof(val: _T) -> NumbaType: ...

def generated_jit(
    func: _F = ...,
    *,
    nopython: bool = False,
    cache: bool = False,
) -> _F | Callable[[_F], _F]: ...

def extending__overload(
    func: Callable[..., object],
    *,
    jit_options: dict[str, bool | int | str] = ...,
    strict: bool = True,
    prefer_literal: bool = False,
) -> Callable[[_F], _F]: ...

def extending__register_jitable(*args: NumbaType, **kwargs: bool) -> Callable[[_F], _F]: ...

def extending__intrinsic(*args: NumbaType, **kwargs: bool) -> Callable[[_F], _F]: ...


# ── Utility functions ──────────────────────────────────────────────

def literally(val: _T) -> _T: ...

def objmode(**types: NumbaType) -> _ObjModeContext: ...


class _ObjModeContext:
    """Context manager for object mode blocks."""
    def __enter__(self) -> _ObjModeContext: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...


def optional_parallel(parallel: bool = True) -> Callable[[_F], _F]: ...
