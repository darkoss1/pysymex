# CHTD-TS: Constraint Hypergraph Treewidth Decomposition with Thompson Sampling for Symbolic Execution

**PySyMex v0.1.0a1 — Architecture and Algorithm Reference**

---

## Abstract

Symbolic execution faces a fundamental scalability barrier: the path explosion problem, where a program with $B$ branch points produces up to $O(2^B)$ feasible paths. PySyMex mitigates this through a novel combination of graph-theoretic structural analysis and online learning. Rather than enumerating paths naively, PySyMex constructs a **Constraint Interaction Graph (CIG)** over branch conditions, partitions independent constraint clusters via Union-Find, and computes an approximate **tree decomposition** of the CIG using minimum-degree elimination. By applying dynamic programming (message passing) over the tree decomposition, the structural path exploration complexity is reduced to $O(N \cdot 2^w)$, where $w$ is the treewidth of the CIG and $w \ll B$ for structured programs. Path scheduling is governed by an **Adaptive Path Manager** using Discounted Thompson Sampling over a Beta-Bernoulli multi-armed bandit, which dynamically allocates exploration budget across DFS, coverage-guided, and random strategies based on real-time, non-stationary reward feedback. Additionally, a theory-aware solver dispatch layer classifies constraint theories and tunes Z3 parameters per query, with automatic escalation to a parallel portfolio solver for hard instances. Together, these components form the CHTD-TS architecture.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Constraint Interaction Graph](#2-constraint-interaction-graph)
3. [Degeneracy-Based Treewidth and Message Passing](#3-degeneracy-based-treewidth-and-message-passing)
4. [Constraint Independence Optimization](#4-constraint-independence-optimization)
5. [Theory-Aware Solver Dispatch and Fast Paths](#5-theory-aware-solver-dispatch-and-fast-paths)
6. [Adaptive Path Manager — Discounted Thompson Sampling](#6-adaptive-path-manager--discounted-thompson-sampling)
7. [System Integration](#7-system-integration)
8. [Complexity Analysis](#8-complexity-analysis)

---

## 1. Introduction

Classical symbolic execution explores program paths by forking at each conditional branch. For a program with $B$ branches, worst-case exploration is $O(2^B)$. In practice, most branches share symbolic variables. CHTD exploits this structure.

The constraint dependencies between branches form a sparse graph. When this graph has bounded treewidth $w$, the effective structural exploration cost drops to $O(N \cdot 2^w)$, where $N$ is the number of branches. For real-world programs composed of independent modules, sequential validation, and localized data flow, $w$ is typically small even when $B$ is in the hundreds. It is important to note this bounds the path space, while the underlying SMT queries remain bounded by their specific theory complexity.

PySyMex implements this through five cooperating subsystems:

| Subsystem | Module | Role |
|-----------|--------|------|
| Constraint Interaction Graph | `core/treewidth.py` | Track variable-sharing between branches |
| Constraint Independence | `core/constraint_independence.py` | Partition constraints into independent clusters |
| Theory-Aware Solver | `core/solver.py` | Theory detection, parameter tuning, portfolio escalation |
| Branch Affinity Fast Path | `execution/opcodes/control.py` | Eliminate discriminator variables from branch conditions |
| Adaptive Path Manager | `analysis/path_manager.py` | Discounted Thompson Sampling over exploration strategies |

---

## 2. Constraint Interaction Graph

### 2.1 Definition

The **Constraint Interaction Graph** (CIG) $G = (V, E)$ is defined as follows:

* **Vertices** $V$: Each branch point (identified by its bytecode program counter $\mathit{pc}$) is a vertex.
* **Edges** $E$: An edge $(b_i, b_j) \in E$ exists if and only if the branch conditions at $b_i$ and $b_j$ share at least one symbolic variable after discriminator normalization.

### 2.2 Discriminator Normalization

PySyMex's `SymbolicValue` type uses a tagged-union encoding with approximately 15 Z3 variables per symbolic value. The `_base_var_name()` function strips type-discriminator suffixes to recover the base name to prevent artificial graph inflation:

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

### 2.3 Incremental Construction

The graph is maintained incrementally during execution. The amortized cost per branch registration is $O(|vars| \cdot d_{\max})$, where $d_{\max}$ is the maximum number of branches sharing any single variable.

### 2.4 Independent Groups (Treewidth-0 Partition)

The method `get_independent_groups()` computes connected components of the CIG via breadth-first search. Branches in different components share no symbolic variables, giving a treewidth of 0 between components.

---

## 3. Degeneracy-Based Treewidth and Message Passing

### 3.1 Treewidth Estimation via Degeneracy

Computing exact treewidth is NP-hard. PySyMex uses the graph degeneracy as an efficiently computable lower bound.

**Definition.** The degeneracy $\delta^*(G)$ of a graph $G$ is:

$$ \delta^*(G) = \max_H \delta_{\min}(H) $$

where $H$ ranges over all subgraphs of $G$ and $\delta_{\min}(H)$ is the minimum degree in $H$.

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

### 3.2 Stabilization Detection

The graph is considered stabilized when a minimum branch count is reached, the estimated treewidth has remained constant for a set threshold, and the treewidth is below a maximum useful boundary.

### 3.3 Tree Decomposition via Minimum-Degree Elimination

PySyMex computes an approximate tree decomposition using the minimum-degree elimination heuristic. While this does not provide a strict constant-factor guarantee for general graphs, it efficiently yields near-optimal decompositions for the specific sparse topologies of program control-flow graphs.

### 3.4 Dynamic Programming (Message Passing) over the Tree

Instead of extracting a global skeleton and brute-forcing adhesion variables—which scales poorly as $|S|$ approaches $O(N)$—PySyMex targets $O(N \cdot 2^w)$ structural complexity via local message passing.

For a tree decomposition $T$, constraints are solved locally within each bag $i$. The valid truth assignments are projected onto the adhesion set $\mathit{adhesion}(i, j)$ and passed as a constrained interface to the parent bag $j$. This confines the exponential blowup strictly to the local bag width $w$.

```python
def propagate_bag_constraints(
    self,
    td: TreeDecomposition,
    solve_local_bag: Callable[[frozenset[int]], bool],
    pass_messages: Callable[[int, int, frozenset[int]], None],
) -> bool:
    """Dynamic programming (message passing) over the tree decomposition.

    Args:
        td: The tree decomposition to traverse.
        solve_local_bag: Callable that checks satisfiability within a bag.
        pass_messages: Callable that projects valid assignments from
            child to parent via the adhesion set.

    Returns:
        True if all bags are locally satisfiable, False otherwise.

    Complexity: O(N · 2^w) where N = number of bags, w = treewidth.
    """
    if not td.bags:
        return True

    # Process bags in reverse order (leaves to root).
    # Bag IDs are assigned in elimination order: bag 0 = first eliminated
    # (leaf-most), bag N-1 = last eliminated (root).
    for bag_id in range(len(td.bags) - 1, -1, -1):
        bag = td.bags.get(bag_id)
        if bag is None:
            continue

        # Solve constraints locally within this bag
        local_sat = solve_local_bag(bag)
        if not local_sat:
            return False

        # Pass messages to parent if exists
        parent = td.get_parent(bag_id)
        if parent is not None:
            edge = (bag_id, parent)
            adhesion = td.adhesion.get(edge, frozenset())
            pass_messages(bag_id, parent, adhesion)

    return True
```

---

## 4. Constraint Independence Optimization

### 4.1 Overview

Complementing the branch-level CIG, PySyMex implements a constraint-level independence optimization. Before submitting a satisfiability query to Z3, the optimizer partitions the accumulated path constraints into independent clusters.

### 4.2 Union-Find Data Structure

Constraint clustering is maintained by a `UnionFind` providing amortized $O(\alpha(n))$ per operation.

```python
class UnionFind:
    def find(self, x: str) -> str:
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            next_x = self._parent[x]
            self._parent[x] = root
            x = next_x
        return root

    def union(self, a: str, b: str) -> str:
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

To avoid repeating full AST walks, PySyMex caches results keyed by Z3's deterministic structural hash.

```python
def _extract_variables(self, expr: z3.ExprRef) -> frozenset[str]:
    key = expr.hash()
    cached_bucket = self._var_cache.get(key)
    if cached_bucket is not None:
        for cached_expr, cached_vars in cached_bucket:
            if z3.eq(expr, cached_expr):
                return cached_vars

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
    return result

```

---

## 5. Theory-Aware Solver Dispatch and Fast Paths

### 5.1 Theory Detection

PySyMex classifies the dominant SMT theory of each query before solving, routing to `qflia`, `qfs`, `qfbv`, or `mixed` configurations based on an AST analysis.

### 5.2 Automatic Portfolio Escalation

When a single-solver check returns unknown or exceeds the time threshold, the solver serializes constraints to SMT-LIB and automatically escalates to a parallel multiprocess portfolio solver.

### 5.3 Branch Affinity Fast Path

When a symbolic value's type is known, a single-sort Z3 expression is emitted. This removes type-discriminator variables from branch conditions, directly reducing treewidth in the constraint interaction graph.

---

## 6. Adaptive Path Manager — Discounted Thompson Sampling

### 6.1 Motivation

Fixed exploration strategies exhibit structural bias. An online learning approach adapts in real time, but standard algorithms fail in the highly non-stationary environment of symbolic execution (where "coverage" rewards naturally dry up over time).

### 6.2 Discounted Multi-Armed Bandit Formulation

The `AdaptivePathManager` maintains three arms (`dfs`, `coverage`, `random`). Each arm $k$ is modeled as a coin with unknown bias $\theta_k \sim \text{Beta}(\alpha_k, \beta_k)$. To handle non-stationarity, PySyMex applies a discount factor $\gamma \in (0, 1)$ (default: 0.95) to gradually forget outdated successes.

### 6.3 Thompson Sampling Algorithm

At each step, the manager selects an arm via Thompson Sampling:

$$ \hat{\theta}_k \sim \text{Beta}(\alpha_k, \beta_k), \quad k^* = \arg\max_k \hat{\theta}_k $$

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

### 6.4 Non-Stationary Reward Feedback

Rewards are normalized to $r \in [0, 1]$ to maintain strict Bayesian conjugate prior validity. Raw rewards are first clamped to $[\text{MIN}, \text{MAX}] = [-5, 10]$, then linearly normalized:

$$ r = \frac{\text{clamp}(\text{reward}, -5, 10) - (-5)}{10 - (-5)} $$

**Typical reward signals:**
- $+10.0$ for discovering a new issue (HIGH severity)
- $+3.0$ for covering a new basic block
- $+1.0$ for covering a new branch
- $-1.0$ for hitting a resource limit
- $-5.0$ for immediate UNSAT (infeasible path)

The update rule incorporates the decay factor $\gamma$ (default 0.95):

$$ \alpha_k \leftarrow \gamma \alpha_k + r $$

$$ \beta_k \leftarrow \gamma \beta_k + (1 - r) $$

```python
def record_reward(self, reward: float) -> None:
    if self._last_arm is None:
        return

    # Normalize reward to [0, 1] for conjugate prior validity
    clamped = max(self._REWARD_MIN, min(self._REWARD_MAX, reward))
    r = (clamped - self._REWARD_MIN) / (self._REWARD_MAX - self._REWARD_MIN)

    # Discounted update: decay prior then add observation
    arm = self._arms[self._last_arm]
    arm[0] = self._gamma * arm[0] + r
    arm[1] = self._gamma * arm[1] + (1.0 - r)

    self._total_rewards += reward
```

This strict formulation achieves robust bounds under non-stationary bandit theory, allowing the algorithm to seamlessly shift strategies as the state space evolves.

---

## 7. System Integration

The CHTD-TS architecture integrates all components in the symbolic execution loop:

### 7.1 Initialization

1. **Constraint Independence Optimizer**: Instantiated per-execution, maintains Union-Find and AST-hash cache.
2. **Constraint Interaction Graph**: Constructed incrementally, wraps the optimizer for variable extraction.
3. **Adaptive Path Manager**: Initialized with Beta priors $(\alpha, \beta)$ and discount factor $\gamma = 0.95$.
4. **Solver**: Configured with theory-aware parameters and portfolio escalation enabled.

### 7.2 Execution Loop

For each program execution:

```
while path_manager.has_states():
    # 1. Path selection (Thompson Sampling)
    state = path_manager.get_next_state()

    # 2. Execute bytecode until branch
    while not at_branch(state):
        execute_instruction(state)

    # 3. Register branch in CIG
    branch_condition = get_branch_condition(state)
    interaction_graph.add_branch(state.pc, branch_condition)

    # 4. Constraint independence slicing
    optimizer.register_constraint(branch_condition)
    relevant = optimizer.slice_for_query(state.constraints, branch_condition)

    # 5. Theory-aware solving
    theory = solver.detect_theory(relevant)
    solver.configure_for_theory(theory)

    result_true = solver.check(relevant + [branch_condition])
    result_false = solver.check(relevant + [Not(branch_condition)])

    # 6. Fork and reward feedback
    reward = compute_reward(result_true, result_false, state)
    path_manager.record_reward(reward)

    if result_true == sat:
        path_manager.add_state(fork_state(state, True))
    if result_false == sat:
        path_manager.add_state(fork_state(state, False))
```

### 7.3 Treewidth Analysis (Offline or Periodic)

When the CIG stabilizes (detected via degeneracy plateau):

1. Compute tree decomposition via minimum-degree elimination
2. Extract adhesion sets and parent relationships
3. Optionally use `propagate_bag_constraints()` for structured path enumeration
4. Report treewidth statistics for diagnostics

### 7.4 Data Flow Summary

```
User Code
   ↓
[VM Execution Loop]
   ↓
Branch Encountered → [CIG: add_branch()] → Treewidth updated
   ↓
Branch Condition → [Optimizer: register_constraint()] → Variables clustered
   ↓
Query Construction → [Optimizer: slice_for_query()] → Minimal constraint set
   ↓
Constraint Set → [Solver: detect_theory()] → Theory classification
   ↓
Theory Config → [Solver: check()] → SAT/UNSAT (with portfolio fallback)
   ↓
Results → [Path Manager: record_reward()] → Beta priors updated
   ↓
New States → [Path Manager: add_state()] → Thompson Sampling queue
```

---

## 8. Complexity Analysis

It is critical to separate the structural path complexity from the underlying SMT theory complexity.

| Metric | Complexity Bound |
| --- | --- |
| Naive Path Exploration | $O(2^B)$ |
| **CHTD Structural Space** | $\mathbf{O(N \cdot 2^w)}$ via DP tree decomposition |
| Total Worst-Case Time | $O(N \cdot 2^w \cdot \mathcal{O}_{\text{SMT}})$ |

Here, $\mathcal{O}_{\text{SMT}}$ represents the complexity class of the dominant theory for the local bag constraints (e.g., NP-complete for QF_LIA, undecidable for nonlinear arithmetic).

**Operational Costs:**
| Operation | Complexity |
|-----------|------------|
| `add_branch(pc, cond)` | $O(|vars| \cdot d_{\max})$ amortized |
| `_compute_degeneracy()` | $O(V + E)$ |
| `register_constraint(c)` | $O(|vars(c)| \cdot \alpha(N))$ amortized |
| `slice_for_query(path, q)` | $O(|path| + |vars(q)| \cdot \alpha(N))$ amortized |
| `_thompson_sample()` | $O(K)$ where $K = 3$ arms |

---

**Author / Inventor: Yassine Lahyani (PySyMex)**
