# pysymex acceleration architecture v3

**Author:** Yassine Lahyani
**Scope:** low-latency CHTD bag evaluation, certified-core reuse, and scheduling support

---

## Purpose

The acceleration layer exists to reduce solver cost without weakening symbolic-execution
correctness. It gives pysymex cheaper ways to evaluate selected path regions, but it does not
change the trust boundary:

```text
Fast backends may propose contradictions.
Only certified contradictions may prune symbolic states.
```

The main performance target is explosion-pruning productivity:

\[
EPP = \frac{PathsPruned}{SolverMilliseconds}
\]

High EPP means one solver proof removes many future paths. The acceleration layer therefore
optimizes for small reusable UNSAT cores, low validation cost, and low-overhead containment checks.

## Position In The Engine

pysymex uses acceleration beneath CHTD-TS and above the exact SMT validation layer.

```text
CHTD-TS selects the path region worth checking.
ACCELERATION evaluates cheap regions and produces local candidates.
SMT validation decides whether a candidate is trusted.
CoreIndex stores certified UNSAT cores for future path pruning.
```

The layer is intentionally asymmetric:

- `UNSAT` is useful only when certified or produced by a trusted exact backend.
- `SAT` from a local or accelerated region is a scheduling signal, not proof that the whole path is
  feasible.
- `UNKNOWN`, timeout, backend mismatch, or translation failure never prune.

## Core Data Model

The acceleration architecture uses canonical branch atoms and sparse masks.

| Concept | Role |
|---|---|
| `BranchAtom` | Context-safe identity for a branch predicate, including expression hash, polarity, theory signature, SSA signature, and memory epoch. |
| `PathMask` | Sparse representation of atoms active on a symbolic path. |
| `CoreMask` | Sparse representation of atoms in a certified UNSAT core. |
| `CoreCertificate` | Proof-carrying record for a reusable contradiction, including backend, formula hashes, theory signature, and recheck status. |
| `AccelCandidate` | Local backend result with `sat`, `unsat`, or `unknown` status. |

Containment is the key operation:

\[
CoreMask \subseteq PathMask \Rightarrow PathFormula \models \bot
\]

This implication is valid only when the core is certified and all atom identities are context-safe.

## Formal Trust Model

Let \(P\) be a symbolic path and \(\Phi(P)\) its full path formula. Let an accelerator evaluate a
local region \(R \subseteq \Phi(P)\).

An acceleration backend can produce one of three semantic classes:

| Backend result | Logical statement |
|---|---|
| Local `sat` | \(\exists m.\ m \models R\) |
| Local `unsat` | \(R \models \bot\) |
| `unknown` | No trusted logical statement |

The only result that can imply anything about the full path is local UNSAT:

\[
R \subseteq \Phi(P) \land R \models \bot \Rightarrow \Phi(P) \models \bot
\]

Local SAT has no equivalent full-path implication:

\[
\exists m.\ m \models R \nRightarrow \exists m.\ m \models \Phi(P)
\]

because constraints outside \(R\) may contradict the local model. This asymmetry is why pysymex uses
accelerator SAT as scheduling information only.

## Proof Sketch: Certified Accelerator Pruning

Assume an accelerator returns an UNSAT candidate over atom set \(C\). The candidate is accepted only
when validation establishes:

\[
\bigwedge_{\phi \in C}\phi \models \bot
\]

For any future path \(P'\) with \(C \subseteq A(P')\):

\[
\Phi(P') =
\left(\bigwedge_{\phi \in C}\phi\right)
\land
\left(\bigwedge_{\psi \in A(P') \setminus C}\psi\right)
\]

Since the first conjunct is unsatisfiable, the conjunction is unsatisfiable:

\[
\Phi(P') \models \bot
\]

Therefore pruning \(P'\) preserves all feasible paths. The proof depends on exact atom identity:
if an atom in \(C\) is reused for a semantically different predicate, the subset premise is false.

## Certified Core Index

pysymex uses an antichain index for verified UNSAT cores. The antichain keeps stronger cores and
removes redundant supersets:

\[
C_1 \subseteq C_2 \land C_1 \models \bot \Rightarrow C_2 \text{ is redundant}
\]

The index also uses a rarest-atom lookup. Instead of scanning every stored core, a path checks
candidate cores attached to atoms already present in the path mask. This keeps pruning cheap enough
to run before expensive solver work.

The index is a correctness boundary. It may prune only with cores that are known UNSAT under the
exact semantics used for the active path.

## Antichain Minimality

Let \(\mathcal{C}\) be the set of certified UNSAT cores. A core \(C_i\) dominates \(C_j\) when:

\[
C_i \subset C_j
\]

and both are UNSAT. Any path pruned by \(C_j\) is also pruned by \(C_i\):

\[
C_j \subseteq A(P) \Rightarrow C_i \subseteq A(P)
\]

Keeping \(C_j\) adds no pruning power. The antichain therefore preserves pruning semantics while
reducing lookup cost and memory pressure.

## Theory Routing

The acceleration layer classifies selected bags by theory signature:

| Theory class | Architectural role |
|---|---|
| Pure Boolean | Candidate fast path for low-latency SAT-style evaluation. |
| Bit-vector | Routed to exact SMT unless a trusted exact backend covers the fragment. |
| Linear arithmetic | Routed to exact SMT validation. |
| Arrays and uninterpreted functions | Routed to exact SMT validation. |
| Mixed or unknown | Falls back to full exact solving. |

This routing keeps the fast path narrow. It prevents a cheap backend from silently approximating
theories that require Z3-level semantics.

## Scheduling Science

pysymex uses Topological Thompson Scheduling as an exploration-order policy, not as a proof system.
The scheduler can choose decomposition, target, path, and budget arms. Its reward favors:

- more frontier paths pruned,
- smaller reusable cores,
- larger subtree reach,
- lower separator width,
- higher core reuse,
- lower solve and minimization cost.

The scheduler is allowed to be wrong. A poor scheduling choice can waste time, but it cannot make an
infeasible path feasible or prune a feasible path because pruning still depends on certified cores.

## Scheduling Reward Rationale

The scheduler's reward is tied to expected pruning utility rather than raw solver success:

\[
U(C) \approx \frac{Reach(C) \cdot Reuse(C)}{Cost(C)}
\]

where \(Reach(C)\) estimates how many frontier descendants may contain the core, \(Reuse(C)\)
estimates how often equivalent atom sets recur, and \(Cost(C)\) includes acceleration and validation
time. This reflects the goal of maximizing proof reuse rather than merely finding isolated UNSAT
bags.

## Safety Boundary

The acceleration layer is sound only under these constraints:

- atom identity includes enough context to avoid accidental core reuse across incompatible paths;
- accelerator-produced UNSAT candidates are rechecked unless the backend is inside the trusted exact
  base;
- SAT, UNKNOWN, timeout, exceptions, and unsupported theories do not prune;
- cached cores remain tied to normalized formulas, solver backend metadata, and theory signatures;
- stale or low-value cores may be evicted for performance, but eviction never affects correctness.

## Related Components

- `pysymex/accel/types.py`
- `pysymex/accel/core_index.py`
- `pysymex/accel/evaluator.py`
- `pysymex/accel/thompson.py`
- `pysymex/core/solver/learner.py`
- `pysymex/execution/executors/core.py`
