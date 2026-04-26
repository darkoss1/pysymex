# pysymex v2: Constraint Hypergraph Treewidth Decomposition with Topological Thompson Sampling

## Architecture and Algorithm Reference

### Abstract
Symbolic execution faces a fundamental scalability barrier: the path explosion problem, where a program with $B$ branch points produces up to $O(2^B)$ feasible paths. pysymex v2 mitigates this through a novel architecture that fuses graph-theoretic structural analysis, SMT minimal unsatisfiable subset (MUS) extraction, and online machine learning.

Rather than relying on flawed dynamic programming (message-passing) algorithms that fail on integer arithmetic, pysymex constructs a Constraint Interaction Graph (CIG) and utilizes a hybrid solver dispatcher. It processes pure boolean logic via lightweight thread-local SAT fast-paths and delegates complex arithmetic to Z3's Conflict-Driven Clause Learning (CDCL) engine using Activation-Literal Core Extraction. This extracts the exact structural contradictions ($\mathcal{C}_{\text{MUS}}$) in a single query.

Path scheduling is governed by an Adaptive Path Manager using a Beta-Bernoulli multi-armed bandit. Instead of blind exploration, pysymex actively hunts for program bottlenecks by scoring extracted failures using the Topological Information Yield ($\mathcal{Y}_{\text{topo}}$) equation. This converts the engine from a linear backtracking explorer into an active structural hunter, effectively pruning millions of downstream paths and dropping constraint-solving bottlenecks by orders of magnitude.

### Table of Contents
1. [Introduction](#1-introduction)
2. [Constraint Interaction Graph](#2-constraint-interaction-graph)
3. [The Solver Engine: MUS Extraction & Hybrid Dispatch](#3-the-solver-engine-mus-extraction--hybrid-dispatch)
4. [Constraint Independence Optimization](#4-constraint-independence-optimization)
5. [Memory-Safe Structural Pruning](#5-memory-safe-structural-pruning)
6. [Adaptive Path Manager — Topological Thompson Sampling](#6-adaptive-path-manager--topological-thompson-sampling)
7. [System Integration](#7-system-integration)
8. [Complexity Analysis](#8-complexity-analysis)
9. [References](#9-references)

---

### 1. Introduction
Classical symbolic execution explores program paths by forking at each conditional branch. For a program with $B$ branches, worst-case exploration is $O(2^B)$. In practice, most branches share symbolic variables.

The constraint dependencies between branches form a sparse graph. pysymex exploits this structure by targeting localized constraint "bags" (low treewidth). However, traditional Constraint Hypergraph Treewidth Decomposition (CHTD) assumes a purely boolean domain and fails catastrophically on the mixed arithmetic required by real-world symbolic execution.

pysymex v2 implements a mathematically sound, path-aware architecture through cooperating subsystems:

| Subsystem | Role |
| :--- | :--- |
| Constraint Interaction Graph (CIG) | Tracks variable-sharing between branches. |
| Hybrid MUS Gatekeeper | Replaces broken message-passing with CDCL core extraction. |
| Constraint Independence | Partitions constraints into independent clusters via Union-Find. |
| Theory-Aware Solver | Theory detection, parameter tuning, and portfolio escalation. |
| Adaptive Path Manager | Topological Thompson Sampling over exploration strategies. |

---

### 2. Constraint Interaction Graph

#### 2.1 Definition
The Constraint Interaction Graph (CIG) $G = (V, E)$ is defined as follows:

*   **Vertices $V$**: Each branch point (identified by its bytecode program counter $\mathit{pc}$) is a vertex.
*   **Edges $E$**: An edge $(b_i, b_j) \in E$ exists if and only if the branch conditions at $b_i$ and $b_j$ share at least one symbolic variable after discriminator normalization.

---

### 3. The Solver Engine: MUS Extraction & Hybrid Dispatch

#### 3.1 The Solution: Activation-Literal MUS Extraction
pysymex extracts the exact mathematical contradiction from a bag using Minimal Unsatisfiable Subsets (MUS) via an assumption-based interface. Every constraint $\Phi_i$ in the bag is wrapped in a newly injected, pure boolean "activation literal" ($\alpha_i$). The engine makes a single query to the SMT solver, forcing all switches to ON ($\alpha = \mathbf{1}$):

$$\mathcal{C}_{\text{MUS}} = \text{ExtractCore} \left( \bigwedge_{i \in B} (\alpha_i \implies \Phi_i) \right) \Bigg|_{\alpha = \mathbf{1}}$$

#### 3.2 Asynchronous Core Learning (v2.5)
To prevent the "2x slowdown" on normal benchmarks, MUS extraction is performed asynchronously. The engine continues optimistic execution on a 'likely feasible' path, strictly bounded by a maximum lookahead depth $K$ to prevent local state explosion, while a background worker thread solves the MUS. Upon an UNSAT return, the sub-tree is pruned and all pending asynchronous queries for that branch are cancelled.

---

### 4. Constraint Independence Optimization
Complementing the branch-level CIG, pysymex implements a constraint-level independence optimization. Constraint clustering is maintained by a UnionFind data structure providing amortized $O(\alpha(n))$ per operation.

---

### 5. Memory-Safe Structural Pruning

#### 5.1 Flyweight State Deduplication
pysymex uses a persistent linked-list structure for `BranchHistory`. Only the delta (the newest branch) is stored at each node.

#### 5.2 Sparse UNSAT Cores
Learned cores ($\mathcal{C}_{\text{MUS}}$) are stored as Run-Length Encoded (RLE) sparse bitsets.

*   **Signature Mapping**: Each branch $PC$ is mapped to a unique integer index $i \in [0, |V|]$.
*   **Pruning Check**: Checking if a path contains a contradiction is evaluated via the strict containment check `(PathMask & CoreMask) == CoreMask`, which executes in time proportional to the sparse core size rather than the total program branch count.

---

### 6. Adaptive Path Manager — Topological Thompson Sampling

#### 6.1 The Topological Information Yield Equation ($\mathcal{Y}_{\text{topo}}$)
When the MUS Extractor finds a contradiction ($\mathcal{C}_{\text{MUS}}$), the path manager scores the failure based on its topological value in the Constraint Interaction Graph ($G$):

$$\mathcal{Y}_{\text{topo}}(\mathcal{C}_{\text{MUS}}, G) = \sigma \left( w \cdot \frac{\sum_{v \in \mathcal{C}_{\text{MUS}}} \text{deg}_G(v)}{|\mathcal{C}_{\text{MUS}}|^\tau} - \beta \right)$$

To ensure compatibility with the Beta-Bernoulli conjugate prior, the yield is mapped to $[0,1]$ via the logistic sigmoid $\sigma$. Here, $w$ scales the topological reward, $\tau \in [0,1]$ penalizes excessively large cores, and $\beta$ sets the baseline threshold for bottleneck relevance.

---

### 7. System Integration
The CHTD-TS v2 architecture integrates all components in the symbolic execution loop:

1.  **User Code**
2.  $\downarrow$
3.  **[VM Execution Loop]**
4.  $\downarrow$
5.  **Branch Encountered** $\rightarrow$ **[CIG: add_branch()]**
6.  $\downarrow$
7.  **Background Thread** $\rightarrow$ **[MUS Extraction]**
8.  $\downarrow$
9.  **Main Thread** $\rightarrow$ **[Lazy Feasibility Check]** (Optimistic Execution)
10. $\downarrow$
11. **Sparse Bitset Compression** $\rightarrow$ **[Memory Optimization]** Core signatures compressed
12. $\downarrow$
13. **Topological Score** $\rightarrow$ **[Path Manager]** calculates $\mathcal{Y}_{\text{topo}}$

---

### 8. Complexity Analysis

| Metric | Complexity Bound |
| :--- | :--- |
| Naive Path Exploration | $O(2^B)$ |
| pysymex v2 Execution | $O(|\mathcal{C}_{\text{MUS}}|)$ amortized containment checks via sparse bitset intersections. |

---

### 9. References
*   Robertson, N., & Seymour, P. D. (1986). *Graph minors. II.*
*   Cadar, C., et al. (2008). *KLEE.*
*   Liffiton, M. H., & Sakallah, K. A. (2008). *Algorithms for computing minimal unsatisfiable subsets.*
*   De Moura, L., & Bjørner, N. (2008). *Z3: An efficient SMT solver.*

**Author & Architect of the pysymex Engine:** Yassine Lahyani
