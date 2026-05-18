# pysymex CHTD-TS architecture v3

**Author:** Yassine Lahyani
**Scope:** proof-carrying path-explosion control through constraint hypergraphs, tree
decomposition, certified UNSAT cores, and Thompson scheduling

---

## Thesis

CHTD-TS is pysymex's architecture for reducing practical path explosion while preserving feasible
paths. It combines three ideas:

```text
CHTD identifies where contradictions are likely to be local.
UNSAT cores provide proof that a path region is impossible.
Topological Thompson Scheduling decides which path region to examine first.
```

The non-negotiable invariant is:

```text
Heuristics may choose exploration order.
Only solver-certified contradictions may prune.
```

## Path Explosion Model

For a path \(P\), let the active path formula be:

\[
\Phi(P) = \bigwedge_{\phi \in A(P)} \phi
\]

where \(A(P)\) is the set of canonical branch atoms active on the path. With \(B\) symbolic
branches, naive exploration can reach:

\[
O(2^B)
\]

candidate paths.

CHTD-TS reduces practical exploration by learning contradictions:

\[
C = \{\phi_1,\ldots,\phi_k\}
\]

such that:

\[
\bigwedge_{\phi \in C}\phi \models \bot
\]

Any future path containing that core is infeasible:

\[
C \subseteq A(P) \Rightarrow \Phi(P) \models \bot
\]

This is the core pruning theorem used by the architecture.

## Formal Objects

CHTD-TS reasons over these mathematical objects:

| Object | Meaning |
|---|---|
| \(A(P)\) | Canonical atom set active on path \(P\). |
| \(\Phi(P)\) | Full path formula induced by \(A(P)\). |
| \(H=(V,E)\) | Constraint hypergraph. Vertices are symbolic entities; hyperedges are constraints. |
| \(T\) | Tree decomposition of \(H\). |
| \(B_t\) | Bag at tree node \(t\). |
| \(S_{t,u}=B_t \cap B_u\) | Separator between adjacent bags. |
| \(C\) | Certified UNSAT core over canonical atoms. |

The running-intersection property of a tree decomposition is central:

\[
\forall v \in V,\ \{t \mid v \in B_t\}\ \text{is connected in}\ T
\]

This property is what makes separator-local reasoning meaningful: all dependencies for a symbolic
entity appear along a connected region of the decomposition tree.

## Runtime Layers

| Layer | Role | May prune? |
|---|---|---:|
| Canonical path model | Normalizes branch atoms, symbolic variables, memory epochs, and theory signatures. | No |
| Constraint hypergraph | Represents dependencies between branch constraints. | No |
| Tree decomposition | Groups related constraints into bags and separators. | No |
| Bag-local solving | Finds small local contradictions. | Only through certified UNSAT |
| Certified core layer | Rechecks, stores, and reuses UNSAT cores. | Yes |
| Core index | Performs sparse containment checks against future paths. | Yes |
| Thompson scheduler | Selects decomposition, bag, path, and budget arms. | No |

## Canonical Branch Atoms

Every branch predicate is represented as a canonical atom. Atom identity includes expression shape
and execution context so that core reuse is not confused by unrelated but textually similar
constraints.

The atom model carries:

- program counter,
- true/false polarity,
- normalized expression hash,
- symbolic variable scope,
- heap object scope,
- array and uninterpreted-function scope,
- theory signature,
- SSA signature,
- memory epoch.

Exact atom containment is the default reuse rule. Alpha-renamed or cross-context reuse requires an
explicit recheck before a core can prune.

## Constraint Hypergraph

CHTD models a path as a hypergraph:

\[
H = (V, E)
\]

where vertices are symbolic entities and each hyperedge is a constraint touching one or more
entities. This representation captures dependency width better than a flat list of path
constraints.

The main structural signal is treewidth. Low-width regions are good candidates for local solving
because contradictions often appear inside small bags before the full path formula is solved.

## Hypergraph Soundness

The hypergraph is an index over formula dependencies, not a replacement for the formula. Each
hyperedge corresponds to a real constraint \(\phi_i\). A bag-local formula is:

\[
\Phi(B_t)=\bigwedge_{\phi_i:\ scope(\phi_i)\subseteq B_t}\phi_i
\]

Because every bag-local formula is a subset of the full path formula:

\[
\Phi(B_t) \subseteq \Phi(P)
\]

UNSAT is monotone upward under conjunction:

\[
\Phi(B_t) \models \bot \Rightarrow \Phi(P) \models \bot
\]

This is why bag-local UNSAT can prune. The reverse is not true: a satisfiable bag does not imply a
satisfiable path because contradictions may involve constraints outside that bag.

## Tree Decomposition

A tree decomposition maps the hypergraph into bags. Each bag contains a subset of vertices and
constraints whose scopes fit inside the bag. Separators connect adjacent bags and summarize shared
variables between subtrees.

The architecture uses bags for local UNSAT discovery. If a bag formula is UNSAT, the whole path is
UNSAT because the bag formula is a subset of the path formula:

\[
B \subseteq \Phi(P) \land B \models \bot \Rightarrow \Phi(P) \models \bot
\]

Local SAT does not prove global SAT. It only means that the selected bag did not contain a
contradiction.

## Separator Reasoning

For adjacent decomposition subtrees \(L\) and \(R\) separated by \(S\), all communication between
the two sides flows through \(S\) under the running-intersection property. A separator summary is
sound only if it preserves the logical effect of the hidden subtree on the separator variables.

For a left subtree formula \(\Phi_L\), a summary \(\sigma(S)\) is an over-approximation when:

\[
\Phi_L \Rightarrow \sigma(S)
\]

An over-approximation is safe for detecting UNSAT only in this direction:

\[
\sigma(S) \land \Phi_R \models \bot \Rightarrow \Phi_L \land \Phi_R \models \bot
\]

because every concrete behavior of \(\Phi_L\) is included in \(\sigma(S)\). If this implication is
not proved, separator summaries remain memoization hints rather than pruning facts.

## Certified Core Pipeline

An UNSAT result becomes reusable only after pysymex has a certified core. The certificate ties the
core to:

- atom identifiers,
- formula and SMT-LIB hashes,
- theory signature,
- decomposition and bag metadata,
- solver backend and version,
- minimization status,
- recheck status.

This proof-carrying representation is what lets pysymex prune later paths cheaply without treating
heuristics as facts.

## Core Antichain

Stored cores form an antichain. If one core is a subset of another, the smaller core is strictly
more useful for pruning:

\[
C_s \subset C_l \land C_s \models \bot
\]

The larger core is redundant because every path containing \(C_l\) also contains \(C_s\). The
antichain keeps the index compact and improves reuse.

## Frontier-Wide Pruning

When a new certified core is inserted, queued frontier paths can be pruned immediately if their
atom masks contain the core mask. This converts one solver proof into many skipped path states and
is the primary practical path-explosion reduction mechanism.

Frontier pruning is sound for the same reason direct path pruning is sound: the queued path already
contains a certified contradictory subset.

## Constraint Independence

pysymex uses dependency information to avoid solving unrelated constraints together. If a branch
query touches only one connected component of the constraint dependency graph, independent
components do not affect that query.

This follows the same principle as classical query slicing in symbolic execution: the solver should
see only the constraints that can influence the result, provided the selected slice is dependency
closed.

## Separator Nogoods

Separators can carry learned contradictions for repeated subtree contexts. A separator nogood is
valid only when:

- the separator atom signature matches,
- the internal contradiction has a certified core,
- reuse conditions preserve the original semantics.

Separator nogoods are therefore a compact memoization layer over decomposition structure, not an
independent proof source.

## Topological Thompson Scheduling

Topological Thompson Scheduling is an adaptive ordering policy. It learns which decomposition,
target, path, and budget choices tend to produce high-value certified cores.

The reward model favors:

- more pruned frontier paths,
- higher centrality of the discovered core,
- smaller core size,
- larger subtree reach,
- smaller separator size,
- higher core reuse,
- lower solve and minimization cost.

The scheduler never owns correctness. It only affects which work is attempted earlier.

## Thompson Scheduling As A Bandit Model

Scheduling choices are modeled as arms in a stochastic bandit. Each arm \(a\) has an unknown reward
distribution over pruning productivity. Thompson sampling maintains a posterior over the reward and
selects arms by sampling from that posterior.

The important scientific separation is:

\[
Policy(a) \rightarrow \text{work ordering}
\]

not:

\[
Policy(a) \rightarrow \text{truth}
\]

The sampled posterior can be statistically wrong without affecting soundness. It changes only the
order in which exact or certifying checks are attempted.

## Exact Solver Fallback

When CHTD, acceleration, slicing, or cached-core checks do not prove infeasibility, pysymex falls
back to exact SMT feasibility checking. This preserves the architecture's conservative behavior:
optimization layers can avoid work or discover reusable proofs, but they do not replace exact
solver semantics for undecided paths.

## Soundness Statement

CHTD-TS is lossless with respect to feasible-path preservation under these conditions:

- CHTD and Thompson Scheduling do not discard states by themselves;
- every prune is backed by exact SMT UNSAT or a rechecked UNSAT certificate;
- atom identity is context-safe;
- timeout, solver unknown, unsupported theory, backend exception, and incomplete modeling are not
  treated as UNSAT;
- cache reuse preserves the formula semantics encoded by the certificate.

## Completeness Envelope

CHTD-TS does not guarantee discovery of every infeasible path before full SMT fallback. Its
completeness envelope is conditional:

\[
\text{If exact fallback is reached and the solver returns definite SAT/UNSAT, feasibility is exact.}
\]

CHTD bag checks are incomplete for global UNSAT because contradictions can span multiple bags:

\[
\forall t,\ \Phi(B_t)\not\models\bot
\nRightarrow
\Phi(P)\not\models\bot
\]

The architecture is therefore a proof-reuse and search-order improvement, not a replacement for
whole-path feasibility.

## Related Components

- `pysymex/execution/executors/core.py`
- `pysymex/core/graph/treewidth.py`
- `pysymex/core/graph/union_find.py`
- `pysymex/core/memory/unsat_core_registry.py`
- `pysymex/core/solver/learner.py`
- `pysymex/core/solver/independence.py`
- `pysymex/accel/core_index.py`
- `pysymex/accel/thompson.py`
