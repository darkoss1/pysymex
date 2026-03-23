"""Type stubs for numba.cuda.random module."""

from __future__ import annotations

import numpy as np

from numba import CUDAStream, DeviceNDArray

def create_xoroshiro128p_states(
    n: int,
    seed: int | None = None,
    subsequence_start: int = 0,
    stream: int | CUDAStream = 0,
) -> DeviceNDArray[np.uint64]:
    """Create Xoroshiro128+ RNG states for GPU threads."""
    ...

def init_xoroshiro128p_states(
    states: DeviceNDArray[np.uint64],
    seed: int,
    subsequence_start: int = 0,
    stream: int | CUDAStream = 0,
) -> None:
    """Initialize existing RNG state array."""
    ...

def xoroshiro128p_uniform_float32(states: DeviceNDArray[np.uint64], index: int) -> np.float32:
    """Generate uniform random float32 in [0, 1)."""
    ...

def xoroshiro128p_uniform_float64(states: DeviceNDArray[np.uint64], index: int) -> np.float64:
    """Generate uniform random float64 in [0, 1)."""
    ...

def xoroshiro128p_normal_float32(states: DeviceNDArray[np.uint64], index: int) -> np.float32:
    """Generate standard normal random float32."""
    ...

def xoroshiro128p_normal_float64(states: DeviceNDArray[np.uint64], index: int) -> np.float64:
    """Generate standard normal random float64."""
    ...

def xoroshiro128p_jump(states: DeviceNDArray[np.uint64], index: int) -> None:
    """Advance RNG state by 2^64 steps."""
    ...

def xoroshiro128p_next(states: DeviceNDArray[np.uint64], index: int) -> np.uint64:
    """Generate raw 64-bit random integer."""
    ...
