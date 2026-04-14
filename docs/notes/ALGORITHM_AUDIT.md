# 🔍 Algorithm Audit & Verification Notes

This document tracks algorithmic opportunities and their verification status against the current PySyMex codebase.

---

## 🔍 Audit Results

### 1. **Thompson Sampling (Path Selection)** ✅ Verified
*   **Audit Observation**: Correctly implemented with non-stationary discounting (γ=0.95).
*   **Code Verification**: `pysymex/execution/strategies/manager.py` implements `AdaptivePathManager` using a Beta-Bernoulli multi-armed bandit with a default `_gamma` of 0.95.
*   **Status**: Solid, no immediate changes needed.

### 2. **Constraint Caching (LRU)** ⚠️ Verified (Needs Improvement)
*   **Audit Observation**: Simple LRU cache with 10K entries. Keyed on hash of constraint structure.
*   **Code Verification**: `pysymex/core/optimization.py` defines `ConstraintCache` with a default `max_size` of 10,000. It uses `structural_hash_sorted` for keys and a secondary discriminator for collision detection.
*   **Potential Improvements**:
    *   **Semantic caching**: Currently `x > 5` and `5 < x` are hashed separately.
    *   **Subsumption**: No current logic to use `x > 10` to satisfy `x > 5`.

### 3. **State Merging** 🔧 Verified (High Risk)
*   **Audit Observation**: Merging based on signature/hash collision, not actual similarity. No SAT check before merge.
*   **Code Verification**: `pysymex/core/optimization.py` uses `compute_state_signature` to group states and `merge_states` to join them. `merge_states` creates `z3.Implies` chains but lacks a `check_sat` call to ensure the merged state is actually feasible.
*   **Issues**:
    *   Could merge SAT with UNSAT states, leading to "zombie" paths.
    *   Signature relies on exact PC and constraint hashes, missing structural similarity.

### 4. **Tree Decomposition (CHTD)** ✅ Verified
*   **Audit Observation**: Fixed with Path-Aware algorithm and MUS extraction.
*   **Code Verification**: Architecture updated in `docs/arch/CHTD_ARCHITECTURE.md` to reflect the new MUS-based structural analysis.

### 5. **Constraint Independence** ⚠️ Verified (Suboptimal)
*   **Audit Observation**: Only splits on shared variables, doesn't exploit arithmetic or boolean structure.
*   **Code Verification**: `pysymex/core/solver/independence.py` uses a standard Union-Find on variable names to cluster constraints.
*   **Problem**: Misses opportunities to partition based on theory (e.g., separating BitVector logic from Integer arithmetic if they don't interact).

---

## 🚀 Recommended Implementation Roadmap

| Priority | Algorithm | Impact | Effort | Verification Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **1** | **Abstract Pre-filter** | ⭐⭐⭐⭐⭐ | Medium | Compare path counts on numeric benchmarks |
| **2** | **Portfolio Solving** | ⭐⭐⭐⭐ | High | Measure wall-clock time on hard-SAT instances |
| **3** | **Incremental SMT** | ⭐⭐⭐ | Medium | Profile `check_sat` overhead with/without push/pop |
| **4** | **Semantic Caching** | ⭐⭐⭐ | Low | Monitor cache hit rate on redundant branch code |
| **5** | **State Merging Fix** | ⭐⭐ | Medium | Ensure no UNSAT states are merged into SAT groups |

---

## 🎯 Quick Wins (Implementation Tasks)

1.  **Fix state merging**: Add a SAT check in `merge_states` before finalizing the merge.
2.  **Improve cache keys**: Implement a normalizer for common relational operators (e.g., always convert `>` to `<`).
3.  **Add constraint subsumption**: Experiment with a "lightweight" implication check using Z3's `implies` for cached results.

**Last Updated**: 2026-04-14
**Verified By**: Gemini CLI
