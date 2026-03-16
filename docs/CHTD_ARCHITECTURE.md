# CHTD-TS: Constraint Hypergraph Treewidth Decomposition with Thompson Sampling for Symbolic Execution

**PySyMex v0.1.0a1 — Architecture and Algorithm Reference**

---

## Abstract

Symbolic execution faces a fundamental scalability barrier: the *path explosion problem*, where a program with $B$ branch points produces up to $O(2^B)$ feasible paths. PySyMex mitigates this through a novel combination of graph-theoretic structural analysis and online learning. Rather than enumerating paths naively, PySyMex constructs a **Constraint Interaction Graph (CIG)** over branch conditions, partitions independent constraint clusters via Union-Find, computes an approximate **tree decomposition** of the CIG using minimum-degree elimination, and extracts a **skeleton** — the minimal set of branch points whose truth assignments determine all others through local propagation. This reduces the effective exploration complexity from $O(2^B)$ to $O(N \cdot 2^w)$, where $w$ is the treewidth of the CIG and $w \ll B$ for structured programs. Path scheduling is governed by an **Adaptive Path Manager** using Thompson Sampling over a Beta-Bernoulli multi-armed bandit, which dynamically allocates exploration budget across DFS, coverage-guided, and random strategies based on real-time reward feedback from the execution loop. Additionally, a **theory-aware solver dispatch** layer classifies constraint theories and tunes Z3 parameters per query, with automatic escalation to a parallel portfolio solver for hard instances. Together, these components form the CHTD-TS architecture.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Constraint Interaction Graph](#2-constraint-interaction-graph)
3. [Degeneracy-Based Treewidth and Skeleton Extraction](#3-degeneracy-based-treewidth-and-skeleton-extraction)
4. [Constraint Independence Optimization](#4-constraint-independence-optimization)
5. [Theory-Aware Solver Dispatch and Fast Paths](#5-theory-aware-solver-dispatch-and-fast-paths)
6. [Adaptive Path Manager — Thompson Sampling](#6-adaptive-path-manager--thompson-sampling)
7. [System Integration](#7-system-integration)
8. [Complexity Analysis](#8-complexity-analysis)

---

## 1. Introduction

Classical symbolic execution explores program paths by forking at each conditional branch. For a program with $B$ branches, worst-case exploration is $O(2^B)$. In practice, most branches share symbolic variables — knowledge gained at one branch constrains others. CHTD exploits this structure.

The insight is that the constraint dependencies between branches form a sparse graph. When this graph has bounded **treewidth** $w$, the effective exploration cost drops to $O(N \cdot 2^w)$, where $N$ is the number of branches. For real-world programs composed of independent modules, sequential validation, and localized data flow, $w$ is typically small (often 0-5) even when $B$ is in the hundreds.

PySyMex implements this through five cooperating subsystems:

| Subsystem | Module | Role |
|-----------|--------|------|
| Constraint Interaction Graph | `core/treewidth.py` | Track variable-sharing between branches |
| Constraint Independence | `core/constraint_independence.py` | Partition constraints into independent clusters |
| Theory-Aware Solver | `core/solver.py` | Theory detection, parameter tuning, portfolio escalation |
| Branch Affinity Fast Path | `execution/opcodes/control.py` | Eliminate discriminator variables from branch conditions |
| Adaptive Path Manager | `analysis/path_manager.py` | Thompson Sampling over exploration strategies |

---

## 2. Constraint Interaction Graph

### 2.1 Definition

The **Constraint Interaction Graph** (CIG) $G = (V, E)$ is defined as follows:

- **Vertices** $V$: Each branch point (identified by its bytecode program counter $\mathit{pc}$) is a vertex.
- **Edges** $E$: An edge $(b_i, b_j) \in E$ exists if and only if the branch conditions at $b_i$ and $b_j$ share at least one symbolic variable after discriminator normalization.

This is the **primal graph** of the constraint interaction hypergraph, where hyper-edges are the variable sets of individual branch conditions.

### 2.2 Discriminator Normalization

PySyMex's `SymbolicValue` type uses a tagged-union encoding with approximately 15 Z3 variables per symbolic value. For example, a symbolic value named `x_42` maps to:

```
x_42_int, x_42_bool, x_42_str, x_42_float, x_42_addr,
x_42_is_int, x_42_is_bool, x_42_is_str, x_42_is_float,
x_42_is_obj, x_42_is_path, x_42_is_none, x_42_is_list,
x_42_is_dict, x_42_array, x_42_len
```

Without normalization, two branches both testing `x_42` would share many individual Z3 variables, inflating the graph with redundant edges. The `_base_var_name()` function strips type-discriminator suffixes to recover the base name:

```python
_DISCRIMINATOR_SUFFIXES = (
    "_is_int", "_is_bool", "_is_str", "_is_float",
    "_is_obj", "_is_path", "_is_none", "_is_list", "_is_dict",
    "_int", "_bool", "_str", "_float", "_addr",
    "_array", "_len",
)

def _base_var_name(z3_var_name: str) -> str:
    for suffix in _DISCRIMINATOR_SUFFIXES:
        if z3_var_name.endswith(suffix):
            return z3_var_name[: -len(suffix)]
    return z3_var_name
```

Suffixes are ordered longest-first to ensure correct matching (e.g., `_is_bool` matches before `_bool`). The resulting `base_vars` set is the granularity used for edge construction.

### 2.3 Incremental Construction

The graph is maintained incrementally during execution. Each call to `add_branch(pc, condition)`:

1. Extracts the raw Z3 variable names from the branch condition via the `ConstraintIndependenceOptimizer`.
2. Applies `_base_var_name()` to obtain `base_vars`.
3. For each base variable, looks up all previously registered branches sharing that variable (via the inverted index `_var_branches`), and adds edges to the adjacency list.
4. Registers the current branch in the inverted index.

The amortized cost per branch registration is $O(|vars| \cdot d_{\max})$, where $d_{\max}$ is the maximum number of branches sharing any single variable.

### 2.4 Independent Groups (Treewidth-0 Partition)

The method `get_independent_groups()` computes connected components of the CIG via breadth-first search. Branches in different components share *no* symbolic variables — their constraints are fully independent — giving a treewidth of 0 between components. Each component can be analyzed in isolation, and if a component is found UNSAT, no further exploration of that component is needed.

---

## 3. Degeneracy-Based Treewidth and Skeleton Extraction

### 3.1 Treewidth Estimation via Degeneracy

Computing exact treewidth is NP-hard. PySyMex uses the **graph degeneracy** (also known as the $k$-core number) as an efficiently computable upper bound.

**Definition.** The degeneracy $\delta^*(G)$ of a graph $G$ is:

$$\delta^*(G) = \max_H \delta_{\min}(H)$$

where $H$ ranges over all subgraphs of $G$ and $\delta_{\min}(H)$ is the minimum degree in $H$.

The degeneracy satisfies $\delta^*(G) \leq \mathit{tw}(G)$ for general graphs, making it a valid lower bound on treewidth. PySyMex stores it as `_estimated_tw` and uses it as a proxy for path-exploration budget decisions.

**Algorithm** (`_compute_degeneracy`): Iterative minimum-degree vertex removal in $O(V + E)$:

```python
def _compute_degeneracy(self) -> int:
    degree = {v: len(ns) for v, ns in self._adjacency.items()}
    for pc in self._branch_info:
        if pc not in degree:
            degree[pc] = 0
    remaining = set(degree.keys())
    max_min_degree = 0
    while remaining:
        v = min(remaining, key=lambda x: degree[x])
        max_min_degree = max(max_min_degree, degree[v])
        remaining.discard(v)
        for neighbor in self._adjacency.get(v, set()):
            if neighbor in remaining:
                degree[neighbor] -= 1
    return max_min_degree
```

The degeneracy is recomputed only when the maximum degree in the graph increases after a new branch registration, avoiding unnecessary recalculations.

### 3.2 Stabilization Detection

The graph is considered **stabilized** when all three conditions hold:

1. At least `min_branches` (default: 6) branches have been registered.
2. The estimated treewidth has not changed for `stability_threshold` (default: 8) consecutive branch additions.
3. The estimated treewidth is at most `max_useful_treewidth` (default: 15).

Stabilization signals that the CIG structure is representative of the full program and skeleton extraction is worthwhile.

### 3.3 Tree Decomposition via Minimum-Degree Elimination

PySyMex computes an approximate tree decomposition using the **minimum-degree elimination** heuristic, which produces a decomposition of width at most $2 \cdot \mathit{tw}_{\mathrm{opt}}(G)$.

**Algorithm** (`compute_tree_decomposition`):

1. Initialize a working copy of the adjacency list.
2. **Elimination loop**: Repeatedly select the vertex $v$ with minimum degree among remaining vertices.
   - Record the **bag** $\{v\} \cup N(v)$ where $N(v)$ is the set of $v$'s remaining neighbors.
   - **Fill-in**: Add edges between all pairs in $N(v)$, making them a clique (the elimination clique).
   - Remove $v$ from the remaining set.
3. **Tree construction**: Connect bag $i$ to the first later bag $j > i$ that shares at least one vertex. The shared vertices form the **adhesion** of the tree edge $(i, j)$.

The resulting `TreeDecomposition` contains:
- `bags`: Mapping from bag ID to the set of branch PCs in that bag.
- `tree_edges`: Edges of the decomposition tree.
- `adhesion`: For each tree edge, the intersection of the two adjacent bags.
- `width`: $w = \max_i |bag_i| - 1$.
- `elimination_order`: The vertex removal sequence (useful for diagnostics).

### 3.4 Skeleton Extraction

The **skeleton** is defined as the union of all adhesion sets:

$$S = \bigcup_{(i,j) \in T} \mathit{adhesion}(i, j)$$

where $T$ is the set of tree edges in the decomposition.

**Operational meaning**: A branch PC appears in the skeleton if and only if it appears in multiple bags of the tree decomposition. These are the "interface" branches that connect different sub-problems. Fixing the truth values of ALL skeleton branches determines the feasibility of all remaining branches through local propagation down the decomposition tree.

```python
def extract_skeleton(self) -> frozenset[int]:
    td = self.compute_tree_decomposition()
    skeleton: set[int] = set()
    for overlap in td.adhesion.values():
        skeleton.update(overlap)
    return frozenset(skeleton)
```

For a program with $B$ branches and skeleton size $|S|$, the exploration cost becomes $O(2^{|S|} \cdot N \cdot 2^w)$ in the worst case, rather than $O(2^B)$. When the CIG decomposes into $k$ independent components (treewidth 0 between components), $|S| = 0$ for inter-component exploration.

---

## 4. Constraint Independence Optimization

### 4.1 Overview

Complementing the branch-level CIG, PySyMex implements a **constraint-level independence** optimization inspired by KLEE (Cadar et al., 2008, Section 4.1). Before submitting a satisfiability query to Z3, the optimizer partitions the accumulated path constraints into independent clusters and sends only the cluster(s) sharing variables with the query. This reduces average query size by 60-90% on real workloads.

### 4.2 Union-Find Data Structure

Constraint clustering is maintained by a `UnionFind` with path compression and union-by-rank, providing amortized $O(\alpha(n))$ per operation, where $\alpha$ is the inverse Ackermann function (effectively $O(1)$).

```python
class UnionFind:
    def find(self, x: str) -> str:
        # Iterative path compression
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            next_x = self._parent[x]
            self._parent[x] = root
            x = next_x
        return root

    def union(self, a: str, b: str) -> str:
        # Union by rank
        root_a, root_b = self.find(a), self.find(b)
        if root_a == root_b:
            return root_a
        if self._rank[root_a] < self._rank[root_b]:
            self._parent[root_a] = root_b
            return root_b
        elif self._rank[root_a] > self._rank[root_b]:
            self._parent[root_b] = root_a
            return root_a
        else:
            self._parent[root_b] = root_a
            self._rank[root_a] += 1
            return root_a
```

### 4.3 Variable Extraction with AST-Hash Caching

Extracting free variables from a Z3 expression requires a full AST walk. To avoid repeating this for the same expression, PySyMex caches results keyed by `expr.hash()` — Z3's structural hash, which is deterministic for a given AST and immune to Python wrapper garbage collection (unlike `id()`).

The cache uses a bucket-based scheme to handle hash collisions: each bucket is a list of `(expr, vars)` pairs, with exact structural equality checked via `z3.eq(expr, cached_expr)`.

```python
def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
    key = expr.hash()
    cached_bucket = self._var_cache.get(key)
    if cached_bucket is not None:
        for cached_expr, cached_vars in cached_bucket:
            if z3.eq(expr, cached_expr):
                return cached_vars  # O(1) cache hit

    # Full AST walk: collect uninterpreted constant names
    names: set[str] = set()
    worklist: list[z3.ExprRef] = [expr]
    seen_ids: set[int] = {key}
    while worklist:
        node = worklist.pop()
        if z3.is_const(node) and node.decl().arity() == 0:
            if node.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                names.add(node.decl().name())
                continue
        for child in node.children():
            child_id = child.hash()
            if child_id not in seen_ids:
                seen_ids.add(child_id)
                worklist.append(child)
    result = frozenset(names)
    # Store in cache
    ...
    return result
```

### 4.4 Constraint Registration and Query Slicing

**Registration** (`register_constraint`): When a new path constraint enters during execution, its variable set is extracted and all variables are merged into the same Union-Find cluster. This eagerly pre-computes the partition structure.

**Slicing** (`slice_for_query`): Given the full list of path constraints and a branch query:

1. Extract the query's variable set and find its Union-Find cluster root(s).
2. For each path constraint, check if any of its variables share a cluster root with the query.
3. Return only the matching constraints.

If no reduction is possible (all constraints are relevant), the original list object is returned to avoid allocation. If the query has no variables (e.g., `z3.BoolVal(True)`), an empty list is returned immediately.

### 4.5 Integration with the Solver

The `IncrementalSolver.is_sat()` method integrates constraint independence as a first-class optimization. For multi-constraint queries, it:

1. Partitions constraints into independent clusters via `_get_independent_clusters()`.
2. If multiple clusters exist, checks each cluster independently against the structural-hash cache and solver.
3. If any single cluster is UNSAT, the entire conjunction is UNSAT — early termination without solving the remaining clusters.

---

## 5. Theory-Aware Solver Dispatch and Fast Paths

### 5.1 Theory Detection

PySyMex classifies the dominant SMT theory of each query before solving. The `_detect_theory()` method walks the Z3 AST with a budget limit of 2000 nodes and returns one of four theory labels:

| Theory | Detected When | Z3 Configuration |
|--------|--------------|-------------------|
| `qflia` | Default (pure linear integer arithmetic) | `smt.arith.solver = 6` (Simplex + Gomory cuts) |
| `qfs` | Any `Z3_SEQ_SORT` or `Z3_RE_SORT` present | `smt.string_solver = "seq"` |
| `qfbv` | Any `Z3_BV_SORT` present | Default parameters |
| `mixed` | Nonlinear multiplication (2+ non-constant args to `Z3_OP_MUL`) or multiple theories | `smt.arith.solver = 2` (auto) |

Theory configuration is applied before each query and reset afterward to prevent parameter leakage between queries. The solver tracks theory classification frequency in `_theory_hits` for diagnostics.

### 5.2 Automatic Portfolio Escalation

When a single-solver `check()` returns `unknown` or exceeds the escalation threshold (default: 500ms), the `IncrementalSolver` automatically escalates to a `PortfolioSolver`. The portfolio solver:

1. Serializes constraints to SMT-LIB format (Z3 objects are not picklable).
2. Launches parallel worker processes via `ProcessPoolExecutor`, one per tactic.
3. The tactic portfolio is `["smt", "qflia", "qfnra", "default"]`.
4. Returns the first definitive result (SAT or UNSAT) from any worker.
5. If a worker reports SAT, the parent process re-solves locally to obtain a concrete model (since models cannot be serialized across processes).

### 5.3 Branch Affinity Fast Path

The `get_truthy_expr()` function in `execution/opcodes/control.py` converts symbolic values to Z3 boolean expressions at branch points. When a value's `affinity_type` is known, a **single-sort** Z3 expression is emitted, bypassing the full disjunctive encoding:

| `affinity_type` | Emitted Expression | Variables Used |
|:---|:---|:---|
| `"bool"` | `value.z3_bool` | 1 (the boolean) |
| `"int"` | `value.z3_int != 0` | 1 (the integer) |
| `"float"` | `value.z3_float != 0` | 1 (the float) |
| `"str"` | `Length(value.z3_str) != 0` | 1 (the string) |
| *unknown* | `Or(And(is_bool, z3_bool), And(is_int, z3_int != 0))` | 4 (discriminators + values) |

The fast path eliminates type-discriminator variables (`is_bool`, `is_int`) from branch conditions. Since these discriminators create edges in the CIG between any branches testing the same symbolic value, removing them **directly reduces treewidth** in the constraint interaction graph. This is a key enabler for CHTD: without it, every branch on a multi-type symbolic value would share discriminator variables, creating a near-clique in the CIG.

---

## 6. Adaptive Path Manager — Thompson Sampling

### 6.1 Motivation

Fixed exploration strategies (DFS, BFS, coverage-guided) exhibit structural bias: DFS goes deep but may miss shallow bugs; coverage-guided finds breadth but wastes budget on infeasible paths. Different programs and even different regions within a program respond differently to each strategy. An online learning approach adapts in real time.

### 6.2 Multi-Armed Bandit Formulation

The `AdaptivePathManager` maintains three **arms**, each corresponding to an exploration sub-strategy:

| Arm | Strategy | Data Structure |
|-----|----------|----------------|
| `dfs` | Depth-first search | Stack (LIFO) |
| `coverage` | Coverage-guided | Min-heap (priority = negative new-PC count) |
| `random` | Random selection | Pool with uniform random indexing |

Each arm $k$ is modeled as a coin with unknown bias $\theta_k$. The prior distribution on $\theta_k$ is a **Beta distribution**:

$$\theta_k \sim \text{Beta}(\alpha_k, \beta_k)$$

with default priors:

| Arm | $\alpha_0$ | $\beta_0$ | Interpretation |
|-----|:---:|:---:|---------------|
| `dfs` | 2.0 | 1.0 | Mildly optimistic (DFS often finds bugs quickly) |
| `coverage` | 2.0 | 1.0 | Mildly optimistic (coverage correlates with bug discovery) |
| `random` | 1.0 | 1.0 | Uninformative (uniform prior) |

### 6.3 Thompson Sampling Algorithm

At each step, the manager selects an arm via Thompson Sampling:

$$\hat{\theta}_k \sim \text{Beta}(\alpha_k, \beta_k), \quad k^* = \arg\max_k \hat{\theta}_k$$

Implementation:

```python
def _thompson_sample(self) -> str:
    best_arm = self.ARM_DFS
    best_sample = -1.0
    for arm_name, (alpha, beta) in self._arms.items():
        sample = random.betavariate(alpha, beta)
        if sample > best_sample:
            best_sample = sample
            best_arm = arm_name
    return best_arm
```

A state is then popped from the selected arm's data structure. If the selected arm is empty, the manager falls back through the other arms in order: DFS, then coverage, then random.

Each state added to the manager is simultaneously enqueued in **all three** sub-strategies (with a unique `entry_id` per `StateEntry` wrapper). A global `_returned_ids` set ensures each state is yielded exactly once, regardless of which arm selects it.

### 6.4 Reward Feedback

After the executor processes the state returned by `get_next_state()`, a reward signal is fed back to update the last-selected arm. The reward is computed in the execution loop (`executor_core.py`):

| Event | Reward |
|-------|--------|
| New issue discovered | $+10.0$ per issue |
| New program counter covered | $+3.0$ per new PC |
| No new coverage and no issues | $-0.5$ |

The update rule is:

$$
\alpha_k \leftarrow \alpha_k + \min(r, 10.0) \quad \text{if } r > 0
$$

$$
\beta_k \leftarrow \beta_k + \min(|r|, 5.0) \quad \text{if } r \leq 0
$$

where $r$ is the reward signal and the caps prevent any single observation from dominating the posterior. This maintains numerical stability while allowing the posterior to shift meaningfully over time.

### 6.5 Theoretical Properties

Thompson Sampling for the Beta-Bernoulli bandit achieves $O(\sqrt{T \log T})$ **Bayesian regret**, where $T$ is the number of rounds. This means:

- The manager converges to the best-performing strategy for each program.
- Suboptimal arms are explored with a frequency that decreases as confidence grows.
- No explicit exploration-exploitation tradeoff parameter is needed (unlike $\epsilon$-greedy or UCB).

The conjugate prior structure ensures exact posterior updates with $O(1)$ computation per step making the per-state overhead negligible compared to Z3 solver calls.

---

## 7. System Integration

### 7.1 Data Flow

The following diagram traces the data flow through the CHTD-TS architecture during a single execution step:

```
SymbolicExecutor.__init__()
  │
  ├─ IncrementalSolver(timeout_ms, use_cache)
  │    └─ ConstraintIndependenceOptimizer()   ←── Union-Find, var cache
  │
  ├─ ConstraintInteractionGraph(solver._optimizer)
  │    └─ Shares the same optimizer instance
  │
  └─ create_path_manager(strategy)
       └─ AdaptivePathManager(priors)  if strategy == ADAPTIVE

_execute_loop()
  │
  ├─ snapshot: coverage_before, issues_before
  │
  ├─ _execute_step(state)
  │    ├─ dispatcher.dispatch(instr, state)
  │    │    └─ control.py: get_truthy_expr(cond)
  │    │         └─ Affinity fast path → single-sort Z3 expression
  │    │         └─ Fork: state_true, state_false (new path_constraints)
  │    │
  │    └─ _process_execution_result(result, state, instructions)
  │         └─ If fork (≥2 new states):
  │              for each new_state:
  │                interaction_graph.add_branch(pc, last_constraint)
  │                  ├─ Extract base_vars
  │                  ├─ Update adjacency via inverted index
  │                  └─ Recompute degeneracy if max degree increased
  │
  ├─ Compute reward from deltas
  │    reward = 10.0 * new_issues + 3.0 * new_coverage - 0.5 * stagnation
  │
  └─ worklist.record_reward(reward)
       └─ Update Beta(α, β) for last-selected arm

execute_function() / execute_code()
  │
  └─ ExecutionResult
       ├─ treewidth_stats = interaction_graph.get_stats()
       └─ solver_stats = solver.get_stats()
```

### 7.2 Constraint Path (Solver Side)

When the solver receives a satisfiability query:

1. **Full-query cache lookup**: Structural hash of the constraint set checked against the LRU cache.
2. **Cluster-level decomposition**: If ≥2 constraints, the independence optimizer partitions them. Each cluster is checked against the cache independently. A single UNSAT cluster short-circuits the entire query.
3. **Theory detection**: The dominant theory is classified via bounded AST walk.
4. **Theory-specific tuning**: Z3 parameters are set for the detected theory.
5. **Solve**: Push constraints, call `check()`, pop.
6. **Escalation**: If `unknown` or slow (>500ms), escalate to the portfolio solver with parallel tactics.
7. **Reset**: Theory-specific parameters are restored to defaults.

---

## 8. Complexity Analysis

| Operation | Complexity |
|-----------|------------|
| `add_branch(pc, cond)` | $O(\|vars\| \cdot d_{\max})$ amortized |
| `_compute_degeneracy()` | $O(V + E)$ |
| `compute_tree_decomposition()` | $O(V^2)$ worst-case (fill-in edges) |
| `extract_skeleton()` | $O(V^2)$ (dominates by decomposition) |
| `get_independent_groups()` | $O(V + E)$ (BFS) |
| `register_constraint(c)` | $O(\|vars(c)\| \cdot \alpha(N))$ amortized |
| `slice_for_query(path, q)` | $O(\|path\| + \|vars(q)\| \cdot \alpha(N))$ amortized |
| `_detect_theory(constraints)` | $O(\min(\|AST\|, 2000))$ |
| `_thompson_sample()` | $O(K)$ where $K = 3$ arms |
| `record_reward(r)` | $O(1)$ |

**End-to-end**: For a program with $B$ branches, $V$ unique branch points, $E$ constraint-sharing edges, and treewidth $w$:

- **Naive symbolic execution**: $O(2^B)$ paths.
- **With CHTD skeleton**: $O(2^{|S|} \cdot N \cdot 2^w)$ where $|S|$ is the skeleton size.
- **With independence partitioning**: $O(\sum_{i=1}^{k} 2^{B_i})$ where $B_i$ is the branch count in component $i$ and $\sum B_i = B$.
- **Solver query reduction**: 60-90% fewer constraints per query via independence slicing.

---

**Author / Inventor: Yassine Lahyani (PySyMex)**
