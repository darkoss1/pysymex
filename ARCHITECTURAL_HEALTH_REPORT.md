# PySyMex: Architectural Health & Optimization Report
**Date:** Sunday, April 12, 2026
**Focus:** Hardware Acceleration, Three-Tier Caching, and CHTD-TS Integration

## Executive Summary
The intelligence suite reveals a "Giant Brain, No Hands" architecture. While PySyMex has world-class infrastructure for acceleration (`accel/`), caching (`analysis/cache/`), and structural pruning (`CHTD`), these systems are largely isolated in "Manager" modules. The low-level "Workhorse" modules (Opcodes, Models, Detectors) are currently bypassing these optimizations, resulting in a **91.7% efficiency gap**.

---

## 1. Hardware Acceleration (Accel) Gap
**Integration Level:** 8.3%
**The "Sink Hole" Effect:** 411 files propagate acceleration flags but never call a hardware kernel.

### Critical Gaps:
*   **VM Isolation:** `pysymex/execution/vm.py` receives `use_h_acceleration` but handles all branching via slow SMT calls. It lacks the "Hook" to bit-slice paths on the GPU.
*   **Opcode Blindness:** `execution/opcodes/base/control.py` (the most branch-heavy logic) is currently 100% unaccelerated.
*   **ISA Limitation:** The current Bytecode ISA is Boolean-only. It cannot yet offload arithmetic or string operations to the GPU.

---

## 2. Three-Tier Caching Gap
**Integration Level:** ~5% (only 3 core files use `structural_hash`)
**The "Re-solving" Problem:** Heavy logic modules are repeatedly solving identical problems.

### Critical Gaps:
*   **The Models Bottleneck:** The `pysymex/models/` directory (Math, Strings, Objects) has **0% cache usage**. Every integer comparison or list operation is likely triggering a fresh Z3 query.
*   **Detector Cold-Paths:** Detectors in `analysis/detectors/formal.py` generate thousands of sub-queries but do not use `TieredCache` to memoize previously proven "Safe" states.
*   **Missing L1/L2 hits:** `structural_hash` is only used in the low-level solver and bytecode compiler. It is missing from the high-level analysis passes.

---

## 3. CHTD-TS Structural Gap
**Integration Level:** Isolated to Management Layer
**The "Reactive vs. Proactive" Problem:** Pruning happens after paths are created, not during.

### Critical Gaps:
*   **VM Loop Disconnection:** `CHTD` (Structural Pruning) is only touched by `verified.py` and `strategies/manager.py`. The VM does not check the "Adhesion Variables" during the `FORK` opcode, allowing the creation of paths that are structurally guaranteed to be UNSAT.
*   **Thompson Sampling (TS) Scope:** Adaptive scheduling is currently "Macro-level" (which file to scan). It needs to be "Micro-level" (which branch to take inside the VM).

---

## 4. Prioritized Action Plan

### Phase 1: Injection (The "Hands")
1.  **VM Branch Hook:** Modify `vm.py` to call `accel.dispatcher.evaluate_bag` when a branch density threshold is met.
2.  **Model Memoization:** Wrap the functions in `pysymex/models/numeric.py` and `strings.py` with `@CachedAnalysis`.
3.  **Opcode Offloading:** Inject `accel` logic into `opcodes/base/compare.py` for symbolic Boolean equality checks.

### Phase 2: Expansion (The "Brain")
1.  **Arithmetic ISA:** Extend `bytecode.py` to support `BV_ADD`, `BV_SUB`, and `BV_MUL`.
2.  **Batch Detectors:** Rewrite formal detectors to submit "Bags" of constraints instead of individual queries.

### Phase 3: Unification
1.  **Structural VM:** Enable the VM to proactively prune branches using the `ConstraintInteractionGraph` provided by CHTD.

---

## 5. Metadata for Future Analysis
*   **Total Core Touchpoints identified:** 5 functions.
*   **Total Internal Support functions:** ~22.
*   **Total Bottleneck Files:** 94 unique source files.
*   **Total Redundancy Instances:** 411 (primarily environment noise).
