"""Deep performance and memory diagnostics with quantitative verdicts.

These tests are intentionally instrumentation-oriented rather than correctness-only.
Each test prints raw numbers and a PASS/WARN/FAIL verdict.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.slow, pytest.mark.benchmark]

import gc
import os
import statistics
import sys
import time
import tracemalloc
from concurrent.futures import ProcessPoolExecutor, as_completed

import z3
from _pytest.monkeypatch import MonkeyPatch

from pysymex.analysis.path_manager import AdaptivePathManager
from pysymex.core.state import VMState
from pysymex.core.constraint_hash import structural_hash
from pysymex.core.memory_model_core import SymbolicHeap
from pysymex.core.memory_model_types import MemoryRegion, SymbolicAddress
from pysymex.core.solver import IncrementalSolver, active_incremental_solver
from pysymex.core.types import FROM_CONST_CACHE, SYMBOLIC_CACHE, SymbolicValue
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.executor_types import ExecutionConfig
from pysymex.h_acceleration.bytecode import compile_constraint
from pysymex.h_acceleration.dispatcher import GPUDispatcher


def _verdict(value: float, warn_threshold: float, fail_threshold: float, higher_is_better: bool) -> str:
    if higher_is_better:
        if value < fail_threshold:
            return "FAIL"
        if value < warn_threshold:
            return "WARN"
        return "PASS"
    if value > fail_threshold:
        return "FAIL"
    if value > warn_threshold:
        return "WARN"
    return "PASS"


def _solver_worker_check_smt(smt_str: str, timeout_ms: int) -> bool:
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.from_string(smt_str)
    return solver.check() == z3.sat


class _TestableSymbolicExecutor(SymbolicExecutor):
    def process_result(self, result: OpcodeResult, state: VMState) -> None:
        self._process_execution_result(result, state, active_instructions=[])

    def collect_chtd_stats(self) -> dict[str, object]:
        return self._collect_chtd_stats()


def _as_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return default


def test_solver_worker_throughput_by_queue_depth() -> None:
    """Measure solver worker throughput for queue depths 1, 10, 100, 1000."""
    x = z3.Int("x")
    s = z3.Solver()
    s.add(x > 0)
    smt_str = s.to_smt2()

    max_workers = min(4, os.cpu_count() or 2)
    queue_depths = [1, 10, 100, 1000]
    rows: list[tuple[int, int, float, float, str]] = []

    try:
        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            # Warm up worker processes to avoid one-time startup skew at depth=1.
            warmup_futures = [
                pool.submit(_solver_worker_check_smt, smt_str, 1000) for _ in range(max_workers)
            ]
            for future in as_completed(warmup_futures):
                _ = future.result(timeout=5)

            for depth in queue_depths:
                start = time.perf_counter()
                futures = [pool.submit(_solver_worker_check_smt, smt_str, 1000) for _ in range(depth)]
                completed = 0
                for future in as_completed(futures):
                    result = future.result(timeout=5)
                    if result:
                        completed += 1
                elapsed = max(time.perf_counter() - start, 1e-9)
                throughput = completed / elapsed
                warn = 5.0 if depth == 1 else 10.0
                fail = 0.5 if depth == 1 else 1.0
                verdict = _verdict(
                    throughput,
                    warn_threshold=warn,
                    fail_threshold=fail,
                    higher_is_better=True,
                )
                rows.append((depth, completed, elapsed, throughput, verdict))
    except (PermissionError, OSError):
        # Some restricted environments block process creation.
        for depth in queue_depths:
            start = time.perf_counter()
            completed = 0
            for _ in range(depth):
                if _solver_worker_check_smt(smt_str, 1000):
                    completed += 1
            elapsed = max(time.perf_counter() - start, 1e-9)
            throughput = completed / elapsed
            verdict = "PASS"
            rows.append((depth, completed, elapsed, throughput, verdict))

    print("[solver-worker-throughput] depth,completed,elapsed_s,tasks_per_s,verdict")
    for depth, completed, elapsed, throughput, verdict in rows:
        print(f"[solver-worker-throughput] {depth},{completed},{elapsed:.6f},{throughput:.2f},{verdict}")
        assert completed == depth
        assert verdict != "FAIL"


def test_constraint_hash_collision_rate() -> None:
    """Measure structural hash collision rate across a generated workload."""
    x = z3.Int("x")
    y = z3.Int("y")
    signatures_by_hash: dict[int, str] = {}
    collisions = 0
    total = 5000

    start = time.perf_counter()
    for i in range(total):
        expr = z3.And(x + i > y - (i % 17), x - y != (i * 31) % 97, x <= i + 1000)
        h = structural_hash([expr])
        sig = expr.sexpr()
        existing = signatures_by_hash.get(h)
        if existing is None:
            signatures_by_hash[h] = sig
        elif existing != sig:
            collisions += 1
    elapsed = max(time.perf_counter() - start, 1e-9)

    collision_rate = collisions / total
    throughput = total / elapsed
    verdict = _verdict(collision_rate, warn_threshold=0.0001, fail_threshold=0.001, higher_is_better=False)

    print(
        "[constraint-hash-collision] total,unique_hashes,collisions,collision_rate,throughput_per_s,verdict"
    )
    print(
        f"[constraint-hash-collision] {total},{len(signatures_by_hash)},{collisions},"
        f"{collision_rate:.8f},{throughput:.2f},{verdict}"
    )
    assert verdict != "FAIL"


def test_symbolic_value_churn_tracemalloc() -> None:
    """Measure SymbolicValue churn and peak memory under allocation pressure."""
    # Keep this deterministic and bounded; this is a diagnostics test, not a stress soak.
    from_const_n = 12000
    symbolic_n = 2000

    tracemalloc.start()
    start = time.perf_counter()
    values: list[SymbolicValue] = []

    for i in range(from_const_n):
        values.append(SymbolicValue.from_const(i))

    for i in range(symbolic_n):
        sv, _ = SymbolicValue.symbolic(f"deep_perf_tmp_{i}")
        values.append(sv)

    elapsed = max(time.perf_counter() - start, 1e-9)
    current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    allocs = from_const_n + symbolic_n
    allocs_per_sec = allocs / elapsed
    peak_mb = peak_bytes / (1024 * 1024)
    current_mb = current_bytes / (1024 * 1024)
    verdict = _verdict(peak_mb, warn_threshold=128.0, fail_threshold=256.0, higher_is_better=False)

    print("[symbolic-value-churn] allocs,elapsed_s,allocs_per_s,current_mb,peak_mb,verdict")
    print(
        f"[symbolic-value-churn] {allocs},{elapsed:.6f},{allocs_per_sec:.2f},"
        f"{current_mb:.2f},{peak_mb:.2f},{verdict}"
    )

    values.clear()
    SYMBOLIC_CACHE.clear()
    FROM_CONST_CACHE.clear()
    gc.collect()

    assert verdict != "FAIL"


def test_symbolic_heap_write_path_cache_metrics() -> None:
    """Measure symbolic write-path candidate cache behavior and heap counters."""
    heap = SymbolicHeap()
    for i in range(128):
        addr = heap.allocate(type_name="obj")
        heap.write(addr, i)

    sym_base = z3.BitVec("sym_base_deep_perf", SymbolicAddress.ADDR_WIDTH)
    sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)

    target = heap.allocate(type_name="obj")
    heap.write(target, 0)

    solver = IncrementalSolver(timeout_ms=1000)
    solver.add(sym_addr.effective_address == target.effective_address)

    token = active_incremental_solver.set(solver)
    try:
        for i in range(40):
            heap.write(sym_addr, i)
    finally:
        active_incremental_solver.reset(token)

    stats = heap.get_stats()
    lookups = stats["candidate_cache_hits"] + stats["candidate_cache_misses"]
    hit_rate = (stats["candidate_cache_hits"] / lookups) if lookups else 0.0
    verdict = _verdict(hit_rate, warn_threshold=0.50, fail_threshold=0.01, higher_is_better=True)

    print(
        "[heap-write-cache] allocations,frees,reads,writes,symbolic_writes,cache_hits,cache_misses,"
        "live_objects,peak_live_objects,hit_rate,verdict"
    )
    print(
        f"[heap-write-cache] {stats['allocations']},{stats['frees']},{stats['reads']},{stats['writes']},"
        f"{stats['symbolic_writes']},{stats['candidate_cache_hits']},{stats['candidate_cache_misses']},"
        f"{stats['live_objects']},{stats['peak_live_objects']},{hit_rate:.4f},{verdict}"
    )

    assert stats["candidate_cache_misses"] >= 1
    assert stats["candidate_cache_hits"] >= 1
    assert stats["candidate_cache_entries"] <= stats["candidate_cache_limit"]
    assert verdict != "FAIL"


def test_symbolic_heap_candidate_cache_is_bounded() -> None:
    """Ensure symbolic candidate cache does not grow unbounded on unique writes."""
    heap = SymbolicHeap()
    for i in range(32):
        heap.write(heap.allocate(type_name="obj"), i)

    solver = IncrementalSolver(timeout_ms=500)
    token = active_incremental_solver.set(solver)
    try:
        # Unique symbolic addresses force unique cache keys.
        for i in range(900):
            sym_base = z3.BitVec(f"dbg_cache_bound_{i}", SymbolicAddress.ADDR_WIDTH)
            sym_addr = SymbolicAddress(region=MemoryRegion.HEAP, base=sym_base)
            heap.write(sym_addr, i)
    finally:
        active_incremental_solver.reset(token)

    stats = heap.get_stats()
    print(
        "[heap-candidate-cache-bound] entries,limit,misses,hits"
    )
    print(
        f"[heap-candidate-cache-bound] {stats['candidate_cache_entries']},"
        f"{stats['candidate_cache_limit']},{stats['candidate_cache_misses']},{stats['candidate_cache_hits']}"
    )
    assert stats["candidate_cache_entries"] <= stats["candidate_cache_limit"]


def test_chtd_hit_and_fallback_rates(monkeypatch: MonkeyPatch) -> None:
    """Measure CHTD invocation hit rate and solver-unavailable fallback rate."""

    class _FakeTreeDecomposition:
        def __init__(self) -> None:
            self.width = 1
            self.bags = [object()]

    class _FakeInteractionGraph:
        def __init__(self) -> None:
            self.branch_info: dict[int, z3.BoolRef] = {}

        def add_branch(self, pc: int, constraint: z3.BoolRef) -> None:
            self.branch_info[pc] = constraint

        def is_stabilized(self) -> bool:
            return True

        def compute_tree_decomposition(self) -> _FakeTreeDecomposition:
            return _FakeTreeDecomposition()

    class _FakeSolver:
        is_gpu_available = False

        def propagate_all(self, td: object, branch_info: object) -> bool:
            _ = td
            _ = branch_info
            return True

    exec_cfg = ExecutionConfig(
        enable_chtd=True,
        enable_h_acceleration=False,
        max_paths=128,
        max_iterations=20000,
        chtd_check_interval=1,
        chtd_adaptive_interval=False,
        enable_cross_function=False,
        enable_abstract_interpretation=False,
        enable_type_inference=False,
    )

    def _solver_available_factory(*, use_gpu: bool) -> object:
        _ = use_gpu
        return _FakeSolver()

    def _solver_unavailable_factory(*, use_gpu: bool) -> None:
        _ = use_gpu
        return None

    def _make_result() -> tuple[OpcodeResult, VMState]:
        state = VMState()
        left = VMState(pc=10, path_constraints=[z3.Bool("dbg_chtd_left")])
        right = VMState(pc=20, path_constraints=[z3.Bool("dbg_chtd_right")])
        return OpcodeResult.branch([left, right]), state

    def _always_feasible(state: VMState) -> bool:
        _ = state
        return True

    monkeypatch.setattr("pysymex.execution.executor_core._get_chtd_solver", _solver_available_factory)
    hit_exec = _TestableSymbolicExecutor(config=exec_cfg)
    monkeypatch.setattr(hit_exec, "_interaction_graph", _FakeInteractionGraph(), raising=False)
    monkeypatch.setattr(hit_exec, "_check_path_feasibility", _always_feasible, raising=False)
    result, state = _make_result()
    hit_exec.process_result(result, state)
    hit_chtd = hit_exec.collect_chtd_stats()
    hit_runs = _as_int(hit_chtd.get("runs", 0))
    skipped_unstable = _as_int(hit_chtd.get("skipped_unstable", 0))
    skipped_size = _as_int(hit_chtd.get("skipped_size", 0))
    opportunities = max(1, hit_runs + skipped_unstable + skipped_size)
    hit_rate = hit_runs / opportunities

    monkeypatch.setattr("pysymex.execution.executor_core._get_chtd_solver", _solver_unavailable_factory)
    fallback_exec = _TestableSymbolicExecutor(config=exec_cfg)
    monkeypatch.setattr(fallback_exec, "_interaction_graph", _FakeInteractionGraph(), raising=False)
    monkeypatch.setattr(fallback_exec, "_check_path_feasibility", _always_feasible, raising=False)
    fallback_result, fallback_state = _make_result()
    fallback_exec.process_result(fallback_result, fallback_state)
    fallback_chtd = fallback_exec.collect_chtd_stats()
    fallback_unavailable = _as_int(fallback_chtd.get("solver_unavailable", 0))
    fallback_runs = _as_int(fallback_chtd.get("runs", 0))
    fallback_rate = fallback_unavailable / max(1, fallback_unavailable + fallback_runs)

    hit_verdict = _verdict(hit_rate, warn_threshold=0.70, fail_threshold=0.10, higher_is_better=True)
    fallback_verdict = _verdict(
        fallback_rate,
        warn_threshold=0.20,
        fail_threshold=1.10,
        higher_is_better=False,
    )

    print(
        "[chtd-hit-fallback] hit_runs,hit_opportunities,hit_rate,hit_verdict,"
        "fallback_unavailable,fallback_runs,fallback_rate,fallback_verdict"
    )
    print(
        f"[chtd-hit-fallback] {hit_runs},{opportunities},{hit_rate:.4f},{hit_verdict},"
        f"{fallback_unavailable},{fallback_runs},{fallback_rate:.4f},{fallback_verdict}"
    )

    assert hit_runs >= 1
    assert fallback_unavailable >= 1
    assert hit_verdict != "FAIL"


def test_gpu_dispatch_overhead_split() -> None:
    """Measure routing/transfer overhead versus backend evaluation latency."""
    x0, x1, x2 = z3.Bools("dbg_gpu_x0 dbg_gpu_x1 dbg_gpu_x2")
    compiled = compile_constraint(z3.And(x0, z3.Or(x1, x2)), ["dbg_gpu_x0", "dbg_gpu_x1", "dbg_gpu_x2"])

    dispatcher = GPUDispatcher(force_backend=None)
    runs = 20
    kernel_times: list[float] = []
    overhead_times: list[float] = []
    selected_backends: list[str] = []

    for _ in range(runs):
        result = dispatcher.evaluate_bag(compiled)
        kernel_times.append(result.kernel_time_ms)
        overhead_times.append(result.routing_cost_ms + result.transfer_time_ms)
        selected_backends.append(result.backend_used.name)

    kernel_median = statistics.median(kernel_times)
    overhead_median = statistics.median(overhead_times)
    overhead_ratio = overhead_median / max(1e-9, overhead_median + kernel_median)
    verdict = _verdict(overhead_ratio, warn_threshold=0.70, fail_threshold=0.95, higher_is_better=False)

    print(
        "[gpu-dispatch-overhead] runs,backend,last_kernel_ms,last_overhead_ms,"
        "median_kernel_ms,median_overhead_ms,overhead_ratio,verdict"
    )
    print(
        f"[gpu-dispatch-overhead] {runs},{selected_backends[-1]},{kernel_times[-1]:.6f},"
        f"{overhead_times[-1]:.6f},{kernel_median:.6f},{overhead_median:.6f},"
        f"{overhead_ratio:.4f},{verdict}"
    )

    assert verdict != "FAIL"


def test_scheduler_memory_per_path() -> None:
    """Measure AdaptivePathManager memory growth per tracked path."""
    manager = AdaptivePathManager()
    tracked_paths = 3000

    tracemalloc.start()
    start_current, start_peak = tracemalloc.get_traced_memory()

    for i in range(tracked_paths):
        manager.add_state(
            VMState(
                pc=i,
                depth=i % 64,
                visited_pcs={i, i + 1, i + 2},
            )
        )

    end_current, end_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    live_delta = max(0, end_current - start_current)
    peak_delta = max(0, end_peak - start_peak)
    bytes_per_path_live = live_delta / tracked_paths
    bytes_per_path_peak = peak_delta / tracked_paths
    manager_stats = manager.get_stats()
    arm_state_bytes = sys.getsizeof(manager_stats)

    verdict = _verdict(
        bytes_per_path_peak,
        warn_threshold=8192.0,
        fail_threshold=16384.0,
        higher_is_better=False,
    )

    print(
        "[scheduler-memory] tracked_paths,live_delta_bytes,peak_delta_bytes,"
        "bytes_per_path_live,bytes_per_path_peak,arm_state_bytes,covered_pcs,verdict"
    )
    print(
        f"[scheduler-memory] {tracked_paths},{live_delta},{peak_delta},"
        f"{bytes_per_path_live:.2f},{bytes_per_path_peak:.2f},{arm_state_bytes},"
        f"{manager_stats.get('covered_pcs', 0)},{verdict}"
    )

    assert verdict != "FAIL"
