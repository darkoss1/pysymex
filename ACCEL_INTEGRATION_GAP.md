# PySyMex: Hardware Acceleration Integration Roadmap

This document outlines the gaps between the current specialized implementation of the `accel/` module and a "Full Integration" state (100% logical coverage).

## 1. The "Sink Hole" Gaps (Flags Propagate but Logic is Missing)

These files receive the `ExecutionConfig` (including `use_h_acceleration = True`) but do not yet act upon it. They are "Aware" but not "Empowered."

*   **`pysymex/execution/vm.py`**: The core Symbolic Virtual Machine receives the config but handles branching naively via Z3. It needs a hook to call `accel.dispatcher.evaluate_bag` during path forking.
*   **`pysymex/execution/executors/verified.py`**: The verified executor ensures correctness but does so purely through SMT checks. It should use `accel` for high-speed state-space validation before falling back to Z3 for formal proof.
*   **`pysymex/analysis/concolic.py`**: The concolic engine explores concrete paths alongside symbolic ones. It currently ignores hardware acceleration, meaning it misses the opportunity to bit-slice test cases at trillions per second.
*   **`pysymex/analysis/autotuner.py`**: The autotuner should theoretically measure `accel/` throughput to decide optimal search strategies, but it currently only monitors SMT latency.

## 2. The "Cold Path" Gaps (Untapped Potential)

These modules contain heavy Boolean or combinatorial logic that is currently 100% SMT-based. These are your primary "Performance Bottlenecks."

*   **`pysymex/execution/opcodes/base/compare.py`**: Boolean comparisons (e.g., `==`, `!=` on symbolic bools) are perfect candidates for the `accel/` ISA but are currently handed to Z3.
*   **`pysymex/execution/opcodes/base/control.py`**: Jump and branch logic is where "Path Explosion" happens. This is the most critical area lacking direct `accel` injection.
*   **`pysymex/analysis/detectors/formal.py`**: Detectors like "Division by Zero" or "Assertion Errors" often generate thousands of simple Boolean sub-queries. These should be batched and sent to the GPU dispatcher.
*   **`pysymex/core/solver/engine.py`**: The `IncrementalSolver` is "accel-blind." It should be modified to detect if a query is purely Boolean and "steal" it for the hardware backend.

## 3. Capability Gaps (ISA Limitations)

The hardware backend itself needs to expand to support the requirements of the core engine.

*   **`pysymex/accel/bytecode.py`**: Currently 100% Boolean. It needs **Integer Bit-Vector (BV) support** to handle arithmetic opcodes (`ADD`, `SUB`, `MUL`) in hardware.
*   **`pysymex/accel/backends/gpu.py`**: Lacks **Memory-Mapped String Buffers**. Adding these would allow accelerated scanning of `str.startswith` or regex logic.
*   **`pysymex/plugins/`**: There is no public API for plugins to register "GPU Kernels." Plugins remain slow because they cannot touch the hardware acceleration pipeline.

## 4. Logical Redundancy (The 91.7% Problem)

*   **411 Files**: These files in the `.tox` and `build/` directories indicate that the distributed version of PySyMex is not shipping with its acceleration "Hot Paths" enabled by default. The build pipeline needs a "Performance Gate" to ensure these paths are wired correctly during installation.

## Summary of Urgency

| Priority | Target | Potential Gain |
| :--- | :--- | :--- |
| **CRITICAL** | `execution/vm.py` | 10x - 100x Faster Path Discovery |
| **HIGH** | `execution/opcodes/base/control.py` | Elimination of Boolean Branch Bottlenecks |
| **MEDIUM** | `analysis/detectors/` | Real-time "Instant" vulnerability scanning |
| **LOW** | `core/solver/engine.py` | Incremental SMT speedup for Boolean sub-problems |
