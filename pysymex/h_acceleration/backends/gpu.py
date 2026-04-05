# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""CuPy NVRTC Backend - Extreme Performance GPU Acceleration.

Provides maximum-performance GPU acceleration for NVIDIA hardware using
direct CUDA C++ compilation via NVRTC (Runtime Compilation).

Key Optimizations:
- Direct CUDA C++ code generation (no Python/Numba overhead)
- 8x thread coarsening (8 chunks per thread iteration)
- Instruction-level parallelism via manual unrolling
- Warp-level shuffle reductions for counting
- Memory coalescing via uint64 writes
- Constraint-specialized kernels (JIT compiled)
- Buffer pooling to eliminate allocation overhead
- LRU kernel cache for fast constraint re-evaluation

Performance: O(2^w * instructions / (cuda_cores * threads_per_block))
  where threads_per_block is adaptive: min(256, max_threads_per_sm), minimum 32
Memory: O(2^w / 8) bytes for output bitmap
"""

from __future__ import annotations

import hashlib
import math
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, SupportsBytes, cast

import numpy as np
import numpy.typing as npt

try:
    import cupy as cp
except ImportError:
    cp = None

from pysymex.h_acceleration.backends import BackendError, BackendInfo, BackendType
from pysymex.h_acceleration.bytecode import Opcode

if TYPE_CHECKING:
    from typing import TypeAlias

    import cupy

    from pysymex.h_acceleration.bytecode import CompiledConstraint

    CupyArray: TypeAlias = cupy.ndarray[np.generic]
    CupyArrayU64: TypeAlias = cupy.ndarray[np.uint64]
    CupyArrayU32: TypeAlias = cupy.ndarray[np.uint32]
    CupyStream: TypeAlias = cupy.Stream
    CupyKernel: TypeAlias = cupy.RawKernel
else:
    CupyArray = object
    CupyArrayU64 = object
    CupyArrayU32 = object
    CupyStream = object
    CupyKernel = object

__all__ = [
    "clear_bitmap_cache",
    "clear_caches",
    "count_sat",
    "evaluate_bag",
    "evaluate_bag_async",
    "evaluate_bag_projected",
    "get_info",
    "get_memory_info",
    "is_available",
    "warmup",
]

MAX_TREEWIDTH: int = 36
MAX_INSTRUCTIONS: int = 4096
THREAD_COARSENING: int = 8
THREADS_PER_BLOCK: int = 256
KERNEL_CACHE_SIZE: int = 64
BITMAP_CACHE_SIZE: int = 16

_device_info: dict[str, str | int] | None = None
_device_lock = threading.Lock()

_kernel_cache: OrderedDict[str, CupyKernel] = OrderedDict()
_kernel_lock = threading.Lock()

_bitmap_cache: OrderedDict[str, tuple[CupyArrayU64 | CupyArrayU32, int]] = OrderedDict()
_bitmap_lock = threading.Lock()


@dataclass
class _BufferPool:
    """Thread-safe GPU buffer pool for zero-allocation hot paths."""

    _free: dict[tuple[int, np.dtype[np.generic]], list[CupyArray]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def acquire(self, n: int, dtype: np.dtype[np.generic]) -> CupyArray:
        """Get a buffer from the pool or allocate a new one."""
        if cp is None:
            raise BackendError("CuPy not installed")
        key = (n, dtype)
        with self._lock:
            pool = self._free.get(key)
            if pool and len(pool) > 0:
                return pool.pop()
        return cp.empty(n, dtype=dtype)

    def release(self, buf: CupyArray) -> None:
        """Return a buffer to the pool for reuse."""
        if not hasattr(buf, "dtype") or not hasattr(buf, "__len__"):
            return
        key = (len(buf), buf.dtype)
        with self._lock:
            if key not in self._free:
                self._free[key] = []
            if len(self._free[key]) < 8:
                self._free[key].append(buf)


_buffer_pool = _BufferPool()


def is_available() -> bool:
    """Check if CUDA is available via CuPy."""
    try:
        if cp is None:
            return False

        _ = cp.cuda.Device(0).compute_capability
        return True
    except Exception:
        return False


def _get_device_info() -> dict[str, str | int]:
    """Get CUDA device information (cached)."""
    global _device_info
    with _device_lock:
        if _device_info is not None:
            return _device_info

        try:
            if cp is None:
                return {"error": "CuPy not installed"}
            dev = cp.cuda.Device()
            free_mem, total_mem = dev.mem_info
            props = cp.cuda.runtime.getDeviceProperties(dev.id)

            _device_info = {
                "name": props["name"].decode()
                if isinstance(props["name"], bytes)
                else str(props["name"]),
                "compute_capability": f"{props['major']}.{props['minor']}",
                "multiprocessors": int(props["multiProcessorCount"]),
                "max_threads_per_block": int(props["maxThreadsPerBlock"]),
                "warp_size": int(props["warpSize"]),
                "total_memory": int(total_mem),
                "free_memory": int(free_mem),
                "clock_rate_mhz": int(props["clockRate"]) // 1000,
            }
        except Exception as e:
            _device_info = {"error": str(e)}

        return _device_info


def _calculate_max_treewidth(total_memory_bytes: int) -> int:
    """Calculate maximum treewidth based on available VRAM."""
    usable_bytes = int(total_memory_bytes * 0.75)
    if usable_bytes <= 0:
        return 20
    max_w = int(math.log2(usable_bytes * 8))
    return min(max_w, MAX_TREEWIDTH)


def get_info() -> BackendInfo:
    """Get backend information."""
    if not is_available():
        return BackendInfo(
            backend_type=BackendType.GPU,
            name="CuPy NVRTC",
            available=False,
            max_treewidth=0,
            error_message="CuPy not available (pip install cupy-cuda12x)",
        )

    info = _get_device_info()
    if "error" in info:
        return BackendInfo(
            backend_type=BackendType.GPU,
            name="CuPy NVRTC",
            available=False,
            max_treewidth=0,
            error_message=str(info["error"]),
        )

    total_memory = info.get("total_memory", 0)
    max_w = _calculate_max_treewidth(int(total_memory))
    total_mb = int(total_memory) // (1024 * 1024)

    return BackendInfo(
        backend_type=BackendType.GPU,
        name=f"CuPy NVRTC ({info.get('name', 'Unknown')})",
        available=True,
        max_treewidth=max_w,
        supports_async=True,
        device_memory_mb=total_mb,
        compute_units=int(info.get("multiprocessors", 1)),
    )


def get_memory_info() -> dict[str, bool | int]:
    """Get current GPU memory usage."""
    if not is_available() or cp is None:
        return {"available": False}
    dev = cp.cuda.Device()
    free, total = dev.mem_info
    return {
        "available": True,
        "free_mb": int(free) // (1024 * 1024),
        "total_mb": int(total) // (1024 * 1024),
        "used_mb": (int(total) - int(free)) // (1024 * 1024),
    }


def _instruction_hash(constraint: CompiledConstraint) -> str:
    """Generate unique hash for constraint's instruction stream."""

    instr_bytes = bytes(cast("SupportsBytes", np.ascontiguousarray(constraint.instructions)))
    return hashlib.sha256(instr_bytes).hexdigest()[:16]


def _bitmap_cache_key(constraint: CompiledConstraint) -> str:
    """Generate cache key for bitmap caching."""
    return f"{_instruction_hash(constraint)}:{constraint.num_variables}"


def _analyze_used_variables(constraint: CompiledConstraint) -> set[int]:
    """Analyze which variables are actually used in the constraint."""
    num_vars = constraint.num_variables
    instrs = constraint.instructions
    used: set[int] = set()

    for instr in instrs:
        op = Opcode(int(instr["opcode"]))
        if op == Opcode.HALT:
            break
        if op == Opcode.LOAD_VAR:
            used.add(int(instr["immediate"]))
        for r in [int(instr["src1"]), int(instr["src2"])]:
            if 1 <= r <= num_vars:
                used.add(r - 1)

        if op == Opcode.ITE and 1 <= int(instr["immediate"]) <= num_vars:
            used.add(int(instr["immediate"]) - 1)

    return used


def _gen_cuda_source(
    constraint: CompiledConstraint,
    mode: str,
    kernel_name: str,
) -> str:
    """Generate optimized CUDA C++ source code for constraint evaluation."""
    num_vars = constraint.num_variables
    instrs = constraint.instructions
    used_vars = _analyze_used_variables(constraint)

    PATTERNS = [
        "0xAAAAAAAAAAAAAAAAULL",
        "0xCCCCCCCCCCCCCCCCULL",
        "0xF0F0F0F0F0F0F0F0ULL",
        "0xFF00FF00FF00FF00ULL",
        "0xFFFF0000FFFF0000ULL",
        "0xFFFFFFFF00000000ULL",
    ]

    if mode == "project":
        lines = [
            f'extern "C" __global__ void {kernel_name}(',
            "    const unsigned long long num_chunks,",
            "    const unsigned long long num_states,",
            "    unsigned int* __restrict__ output,",
            "    const unsigned int adhesion_mask,",
            "    const unsigned char* __restrict__ adhesion_mapping",
            ") {",
            "    const unsigned long long tid = blockIdx.x * blockDim.x + threadIdx.x;",
            "    const unsigned long long stride = gridDim.x * blockDim.x;",
        ]
    else:
        lines = [
            f'extern "C" __global__ void {kernel_name}(',
            "    const unsigned long long num_chunks,",
            "    const unsigned long long num_states,",
            "    unsigned long long* __restrict__ output",
            ") {",
            "    const unsigned long long tid = blockIdx.x * blockDim.x + threadIdx.x;",
            "    const unsigned long long stride = gridDim.x * blockDim.x;",
        ]

    if mode == "count":
        lines.append("    unsigned long long local_count = 0ULL;")

    for i in range(min(num_vars, 6)):
        if i in used_vars:
            lines.append(f"    const unsigned long long c{i + 1} = {PATTERNS[i]};")

    lines.append(
        f"    for (unsigned long long base = tid * {THREAD_COARSENING}; base < num_chunks; base += stride * {THREAD_COARSENING}) {{"
    )

    for c in range(THREAD_COARSENING):
        lines.append(f"        const unsigned long long chunk{c} = base + {c}ULL;")
        lines.append(f"        const unsigned long long base_tid{c} = chunk{c} << 6;")

    for i in range(min(num_vars, 6)):
        if i in used_vars:
            for c in range(THREAD_COARSENING):
                lines.append(f"        unsigned long long r{i + 1}_{c} = c{i + 1};")

    for i in range(6, num_vars):
        if i in used_vars:
            bit = i - 6
            for c in range(THREAD_COARSENING):
                lines.append(
                    f"        unsigned long long r{i + 1}_{c} = 0ULL - ((chunk{c} >> {bit}ULL) & 1ULL);"
                )

    regs_to_init: set[int] = set()
    for instr in instrs:
        if int(instr["opcode"]) != 0xFF:
            regs_to_init.add(int(instr["dst"]))
    regs_to_init.add(0)

    for r in list(regs_to_init):
        if 1 <= r <= num_vars:
            regs_to_init.discard(r)
    for r in sorted(regs_to_init):
        for c in range(THREAD_COARSENING):
            lines.append(f"        unsigned long long r{r}_{c} = 0ULL;")

    for instr in instrs:
        op = Opcode(int(instr["opcode"]))
        if op == Opcode.HALT:
            break
        if op == Opcode.NOP:
            continue

        dst, s1, s2, imm = (
            int(instr["dst"]),
            int(instr["src1"]),
            int(instr["src2"]),
            int(instr["immediate"]),
        )

        for c in range(THREAD_COARSENING):
            if op == Opcode.AND:
                lines.append(f"        r{dst}_{c} = r{s1}_{c} & r{s2}_{c};")
            elif op == Opcode.OR:
                lines.append(f"        r{dst}_{c} = r{s1}_{c} | r{s2}_{c};")
            elif op == Opcode.NOT:
                lines.append(f"        r{dst}_{c} = ~r{s1}_{c};")
            elif op == Opcode.XOR:
                lines.append(f"        r{dst}_{c} = r{s1}_{c} ^ r{s2}_{c};")
            elif op == Opcode.LOAD_VAR:
                lines.append(f"        r{dst}_{c} = r{imm + 1}_{c};")
            elif op == Opcode.LOAD_TRUE:
                lines.append(f"        r{dst}_{c} = 0xFFFFFFFFFFFFFFFFULL;")
            elif op == Opcode.LOAD_FALSE:
                lines.append(f"        r{dst}_{c} = 0ULL;")
            elif op == Opcode.COPY:
                lines.append(f"        r{dst}_{c} = r{s1}_{c};")
            elif op == Opcode.IMPLIES:
                lines.append(f"        r{dst}_{c} = (~r{s1}_{c}) | r{s2}_{c};")
            elif op == Opcode.IFF or op == Opcode.EQ:
                lines.append(f"        r{dst}_{c} = ~(r{s1}_{c} ^ r{s2}_{c});")
            elif op == Opcode.NE:
                lines.append(f"        r{dst}_{c} = r{s1}_{c} ^ r{s2}_{c};")
            elif op == Opcode.ITE:
                lines.append(
                    f"        r{dst}_{c} = (r{s1}_{c} & r{s2}_{c}) | ((~r{s1}_{c}) & r{imm}_{c});"
                )
            elif op == Opcode.NAND:
                lines.append(f"        r{dst}_{c} = ~(r{s1}_{c} & r{s2}_{c});")
            elif op == Opcode.NOR:
                lines.append(f"        r{dst}_{c} = ~(r{s1}_{c} | r{s2}_{c});")

    for c in range(THREAD_COARSENING):
        lines.append(f"        unsigned long long res{c} = r0_{c};")
        lines.append(f"        if (chunk{c} < num_chunks) {{ ")
        lines.append(f"            if (base_tid{c} + 64ULL > num_states) {{ ")
        lines.append(
            f"                const unsigned long long remaining = num_states - base_tid{c};"
        )
        lines.append(f"                res{c} &= (1ULL << remaining) - 1ULL;")
        lines.append("            } ")
        lines.append("        }  else { ")
        lines.append(f"            res{c} = 0ULL; ")
        lines.append("        } ")

    if mode == "count":
        popcs = " + ".join(f"__popcll(res{c})" for c in range(THREAD_COARSENING))
        lines.append(f"        local_count += {popcs};")
    elif mode == "project":
        for c in range(THREAD_COARSENING):
            lines.append(f"        if (chunk{c} < num_chunks && res{c} != 0ULL) {{ ")
            lines.append("            for (int bit = 0; bit < 64; ++bit) { ")
            lines.append(f"                if ((res{c} >> bit) & 1ULL) {{ ")
            lines.append(f"                    unsigned long long state_tid = base_tid{c} + bit;")
            lines.append("                    if (state_tid < num_states) { ")
            lines.append("                        unsigned int adhesion_idx = 0;")
            lines.append(f"                        for (int i = 0; i < {num_vars}; ++i) {{ ")
            lines.append("                            if ((adhesion_mask >> i) & 1) { ")
            lines.append("                                if ((state_tid >> i) & 1ULL) { ")
            lines.append(
                "                                    adhesion_idx |= (1U << adhesion_mapping[i]);"
            )
            lines.append("                                } ")
            lines.append("                            } ")
            lines.append("                        } ")
            lines.append("                        unsigned int word_idx = adhesion_idx >> 5;")
            lines.append("                        unsigned int bit_pos = adhesion_idx & 31;")
            lines.append("                        atomicOr(&output[word_idx], 1U << bit_pos);")
            lines.append("                    } ")
            lines.append("                } ")
            lines.append("            } ")
            lines.append("        } ")
    else:
        for c in range(THREAD_COARSENING):
            lines.append(f"        if (chunk{c} < num_chunks) output[chunk{c}] = res{c};")

    lines.append("    }")

    if mode == "count":
        lines.append("    #pragma unroll")
        lines.append("    for (int delta = 16; delta > 0; delta >>= 1) {")
        lines.append("        local_count += __shfl_down_sync(0xFFFFFFFF, local_count, delta);")
        lines.append("    }")
        lines.append("    if ((threadIdx.x & 31) == 0) {")
        lines.append("        atomicAdd((unsigned long long*)output, local_count);")
        lines.append("    }")

    lines.append("}")
    return "\n".join(lines)


def _get_optimal_launch_config(constraint: CompiledConstraint, num_chunks: int) -> tuple[int, int]:
    info = _get_device_info()
    num_sms = int(info.get("multiprocessors", 48))
    hw_regs_per_thread = int(constraint.register_count * 2 * 1.2)
    hw_regs_per_thread = max(hw_regs_per_thread, 1)
    max_threads_per_sm = 65536 // hw_regs_per_thread
    max_threads_per_sm = (max_threads_per_sm // 32) * 32
    threads_per_block = min(256, max_threads_per_sm)
    threads_per_block = max(32, threads_per_block)
    blocks_per_sm = max(1, max_threads_per_sm // threads_per_block)
    num_blocks = num_sms * blocks_per_sm
    threads_total = num_chunks // THREAD_COARSENING
    blocks_needed = (threads_total + threads_per_block - 1) // threads_per_block
    num_blocks = min(num_blocks, blocks_needed)
    num_blocks = max(num_blocks, num_sms)
    return num_blocks, threads_per_block


def _get_kernel(constraint: CompiledConstraint, mode: str) -> CupyKernel:
    if cp is None:
        raise BackendError("CuPy not installed")
    cache_key = f"{_instruction_hash(constraint)}_{constraint.num_variables}_{mode}"
    with _kernel_lock:
        if cache_key in _kernel_cache:
            _kernel_cache.move_to_end(cache_key)
            return _kernel_cache[cache_key]
    kernel_name = f"kernel_{cache_key}"
    src = _gen_cuda_source(constraint, mode=mode, kernel_name=kernel_name)
    try:
        module = cp.RawModule(
            code=src, options=("-std=c++11", "--use_fast_math"), name_expressions=[kernel_name]
        )
        kernel = module.get_function(kernel_name)
    except Exception as e:
        raise BackendError(f"Kernel compilation failed: {e}\n\nGenerated code:\n{src}") from e
    with _kernel_lock:
        _kernel_cache[cache_key] = kernel
        while len(_kernel_cache) > KERNEL_CACHE_SIZE:
            _kernel_cache.popitem(last=False)
    return kernel


def evaluate_bag(constraint: CompiledConstraint) -> npt.NDArray[np.uint8]:
    if not is_available() or cp is None:
        raise BackendError("CuPy GPU backend not available")
    from pysymex.h_acceleration.bytecode_optimizer import optimize

    constraint, _ = optimize(constraint)
    cache_key = _bitmap_cache_key(constraint)
    with _bitmap_lock:
        if cache_key in _bitmap_cache:
            d_bitmap, num_vars = _bitmap_cache[cache_key]
            _bitmap_cache.move_to_end(cache_key)
            num_states = 1 << num_vars

            return cast(
                "npt.NDArray[np.uint8]",
                cp.asnumpy(d_bitmap).view(np.uint8)[: ((num_states + 7) // 8)],
            )
    w = constraint.num_variables
    info = get_info()
    if w > info.max_treewidth:
        raise ValueError(f"Treewidth {w} exceeds GPU limit ({info.max_treewidth})")
    num_states = 1 << w
    num_chunks = (num_states + 63) // 64
    d_output = _buffer_pool.acquire(num_chunks, np.dtype(np.uint64))
    kernel = _get_kernel(constraint, mode="eval")
    blocks, threads = _get_optimal_launch_config(constraint, num_chunks)
    kernel((blocks,), (threads,), (np.uint64(num_chunks), np.uint64(num_states), d_output))
    cp.cuda.Device().synchronize()
    with _bitmap_lock:
        _bitmap_cache[cache_key] = cast("tuple[CupyArrayU64 | CupyArrayU32, int]", (d_output, w))
        while len(_bitmap_cache) > BITMAP_CACHE_SIZE:
            _, (old_buf, _) = _bitmap_cache.popitem(last=False)
            _buffer_pool.release(old_buf)

    return cast(
        "npt.NDArray[np.uint8]", cp.asnumpy(d_output).view(np.uint8)[: ((num_states + 7) // 8)]
    )


def count_sat(constraint: CompiledConstraint) -> int:
    if not is_available() or cp is None:
        raise BackendError("CuPy GPU backend not available")
    from pysymex.h_acceleration.bytecode_optimizer import optimize

    constraint, _ = optimize(constraint)
    w = constraint.num_variables
    info = get_info()
    if w > info.max_treewidth:
        raise ValueError(f"Treewidth {w} exceeds GPU limit ({info.max_treewidth})")
    num_states = 1 << w
    num_chunks = (num_states + 63) // 64
    d_count = cp.zeros(1, dtype=np.uint64)
    kernel = _get_kernel(constraint, mode="count")
    blocks, threads = _get_optimal_launch_config(constraint, num_chunks)
    kernel((blocks,), (threads,), (np.uint64(num_chunks), np.uint64(num_states), d_count))
    cp.cuda.Device().synchronize()
    return int(d_count.get()[0])


def evaluate_bag_async(
    constraint: CompiledConstraint, stream: CupyStream | None = None
) -> tuple[CupyArrayU64, CupyStream]:
    if not is_available() or cp is None:
        raise BackendError("CuPy GPU backend not available")
    from pysymex.h_acceleration.bytecode_optimizer import optimize

    constraint, _ = optimize(constraint)
    if stream is None:
        stream = cp.cuda.Stream()
    stream_obj = cast("CupyStream", stream)
    w = constraint.num_variables
    num_states = 1 << w
    num_chunks = (num_states + 63) // 64
    d_output = _buffer_pool.acquire(num_chunks, np.dtype(np.uint64))
    kernel = _get_kernel(constraint, mode="eval")
    blocks, threads = _get_optimal_launch_config(constraint, num_chunks)
    with stream_obj:
        kernel((blocks,), (threads,), (np.uint64(num_chunks), np.uint64(num_states), d_output))
    return cast("tuple[CupyArrayU64, CupyStream]", (d_output, stream_obj))


def evaluate_bag_projected(
    constraint: CompiledConstraint, adhesion_vars: list[str], bag_vars: list[str]
) -> npt.NDArray[np.uint8]:
    if not is_available() or cp is None:
        raise BackendError("CuPy GPU backend not available")
    from pysymex.h_acceleration.bytecode_optimizer import optimize

    constraint, _ = optimize(constraint)
    adhesion_indices = [bag_vars.index(v) for v in adhesion_vars if v in bag_vars]
    w_adhesion = len(adhesion_vars)
    num_adhesion_states = 1 << w_adhesion
    projected = np.zeros((num_adhesion_states + 7) // 8, dtype=np.uint8)
    if not adhesion_indices:
        return projected
    cache_key = f"{_bitmap_cache_key(constraint)}_proj_{hash(tuple(adhesion_indices))}"
    with _bitmap_lock:
        if cache_key in _bitmap_cache:
            d_bitmap, _ = _bitmap_cache[cache_key]
            _bitmap_cache.move_to_end(cache_key)
            return cast(
                "npt.NDArray[np.uint8]",
                cp.asnumpy(d_bitmap).view(np.uint8)[: ((num_adhesion_states + 7) // 8)],
            )
    w = constraint.num_variables
    num_states = 1 << w
    num_chunks = (num_states + 63) // 64
    proj_words = (num_adhesion_states + 31) // 32
    d_output = cp.zeros(proj_words, dtype=np.uint32)
    adhesion_mask = np.uint32(0)
    adhesion_mapping = np.zeros(32, dtype=np.uint8)
    for i, var in enumerate(bag_vars):
        if var in adhesion_vars:
            adhesion_mask |= 1 << i
            adhesion_mapping[i] = adhesion_vars.index(var)
    d_mapping = cp.asarray(adhesion_mapping)
    kernel = _get_kernel(constraint, mode="project")
    blocks, threads = _get_optimal_launch_config(constraint, num_chunks)
    kernel(
        (blocks,),
        (threads,),
        (np.uint64(num_chunks), np.uint64(num_states), d_output, adhesion_mask, d_mapping),
    )
    cp.cuda.Device().synchronize()
    with _bitmap_lock:
        _bitmap_cache[cache_key] = (d_output, w_adhesion)
        while len(_bitmap_cache) > BITMAP_CACHE_SIZE:
            _, (old_buf, _) = _bitmap_cache.popitem(last=False)
            if hasattr(old_buf, "dtype") and old_buf.dtype == np.dtype(np.uint64):
                _buffer_pool.release(old_buf)

    return cast(
        "npt.NDArray[np.uint8]",
        cp.asnumpy(d_output).view(np.uint8)[: ((num_adhesion_states + 7) // 8)],
    )


def warmup() -> None:
    if not is_available():
        return
    try:
        import z3

        from pysymex.h_acceleration.bytecode import compile_constraint

        a, b = z3.Bools("a b")
        constraint = compile_constraint(z3.And(a, b), ["a", "b"])
        evaluate_bag(constraint)
        count_sat(constraint)
    except Exception:
        import logging as _logging

        _logging.getLogger(__name__).debug("GPU warmup failed", exc_info=True)


def clear_caches() -> None:
    global _kernel_cache, _bitmap_cache
    with _kernel_lock:
        _kernel_cache.clear()
    with _bitmap_lock:
        for buf, _ in _bitmap_cache.values():
            _buffer_pool.release(buf)
        _bitmap_cache.clear()


def clear_bitmap_cache() -> None:
    global _bitmap_cache
    with _bitmap_lock:
        for buf, _ in _bitmap_cache.values():
            _buffer_pool.release(buf)
        _bitmap_cache.clear()
