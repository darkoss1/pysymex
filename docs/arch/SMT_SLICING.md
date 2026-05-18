# pysymex SMT slicing architecture v3

**Author:** Yassine Lahyani
**Scope:** exact SMT fallback, dependency-closed query slicing, solver-cache reuse, and certified
UNSAT pruning

---

## Purpose

SMT slicing is pysymex's exact solving layer for reducing repeated Z3 work while preserving solver
meaning. It lowers query cost by reusing path prefixes, slicing independent constraints, caching
translated ASTs, and reusing certified UNSAT cores.

The core invariant is:

```text
Only exact SMT UNSAT or a rechecked UNSAT certificate may prune symbolic states.
```

The layer can reduce formulas before solving, but every reduction has a soundness condition.

## Solver Result Semantics

| Solver outcome | Architectural meaning |
|---|---|
| `sat` | The checked formula is feasible under the encoded model. |
| `unsat` | The checked formula is infeasible and may produce a core. |
| `unknown` | No definite feasibility answer. It cannot prune and cannot verify success. |
| timeout | Treated as unknown or inconclusive. |
| exception | Explicit solver failure or blocked state, not silent fallback. |

This distinction is central to bug-report trust. pysymex must not report a definite bug or definite
verification result when feasibility is unknown.

## Formal Query Model

An SMT query has the form:

\[
Q = \Phi_{prefix} \land \Phi_{suffix} \land \psi
\]

where \(\Phi_{prefix}\) is the shared path prefix, \(\Phi_{suffix}\) is the current path-specific
suffix, and \(\psi\) is the branch, bug condition, contract obligation, or validation query.

SMT slicing replaces \(Q\) with a smaller query \(Q'\) only when the replacement preserves the
answer needed by the caller. For SAT answers, this requires dependency closure or a proven semantic
equivalence. For UNSAT pruning, it is enough that the checked formula is a subset or sound summary
whose contradiction implies contradiction of the original query.

## Incremental Prefix Solving

Symbolic paths often share long prefixes. pysymex uses an incremental solver so a path check can
reuse constraints already asserted for a common prefix and focus only on the divergent suffix.

Prefix reuse is safe when the active solver context exactly matches the path prefix. A stack or
context mismatch forces a full rebuild because stale assertions would corrupt feasibility results.

## Prefix Reuse Invariant

Let the active solver stack contain:

\[
\Gamma = [\phi_1,\ldots,\phi_k]
\]

and the path prefix be:

\[
\Phi_k = \bigwedge_{i=1}^{k}\phi_i
\]

Prefix reuse is valid exactly when \(\Gamma\) and \(\Phi_k\) are syntactically and contextually the
same ordered constraint sequence. If a solver contains any stale constraint \(\chi\), the checked
query becomes:

\[
\Phi_k \land \chi \land \psi
\]

which can produce false UNSAT. If a required prefix constraint is missing, the checked query becomes
an under-approximation that can produce false SAT. Both cases break diagnostic trust, hence the
strict synchronization invariant.

## Constraint Independence

The constraint-independence optimizer partitions constraints by shared symbolic dependencies. A
query only needs constraints from components that can affect that query.

For a query \(Q\) and path constraints \(\Phi\), a sliced formula \(S\) is valid for SAT only when
the slice is dependency closed:

\[
Vars(Q \cup S) \cap Vars(\Phi \setminus S) = \varnothing
\]

Without dependency closure, a missing prefix constraint can turn an infeasible path into an
apparently feasible one.

## Proof Sketch: Dependency-Closed SAT Preservation

Let \(\Phi = S \land R\), where \(S\) is the selected slice and \(R\) is the removed remainder. If
the slice is dependency closed with respect to query \(Q\), then variables in \(R\) are disjoint
from variables in \(S \land Q\):

\[
Vars(R) \cap Vars(S \land Q)=\varnothing
\]

If \(S \land Q\) is SAT with model \(m_S\), and \(R\) is independently SAT with model \(m_R\), the
models can be combined because they assign disjoint symbols:

\[
m = m_S \cup m_R
\]

and:

\[
m \models S \land R \land Q
\]

The preservation depends on \(R\) being independently feasible or already known feasible as part of
a verified prefix. If removed constraints share variables with the query slice, the model-combining
argument fails.

## Semantic Reduction

Semantic reduction removes constraints only when another trusted domain proves they add no new
information for the query. For example, an abstract domain may prove that a bound is already implied
by stronger retained constraints.

The reduction is sound only when implication is proved:

\[
S \models c
\]

If implication is not established, the constraint remains in the SMT formula.

## Proof Sketch: Subsumption Reduction

If a retained formula \(S\) implies a removed constraint \(c\):

\[
S \models c
\]

then:

\[
S \land c \equiv S
\]

because \(c\) adds no models beyond those already satisfying \(S\). Dropping \(c\) preserves both
SAT and UNSAT answers for the reduced formula. This is why domain-subsumption reduction requires a
proof of implication rather than a heuristic similarity score.

## Translation And Cache Model

SMT execution pays for both formula construction and solver time. pysymex uses structural hashes and
theory signatures to cache:

- Z3 AST translations across compatible contexts;
- sliced prefix closures;
- solver check results tied to structural context;
- validated UNSAT cores;
- component-level feasibility facts.

Cache hits are correctness-preserving only when keys encode enough context to avoid cross-formula or
cross-context reuse.

## UNSAT Core Reuse

When Z3 proves a subset of constraints UNSAT, pysymex can store a certified core. Future paths whose
atom masks contain that core are infeasible without another full solver query.

The reuse principle is:

\[
C \models \bot \land C \subseteq \Phi(P) \Rightarrow \Phi(P) \models \bot
\]

This is the same proof basis used by CHTD-TS and the acceleration layer. SMT slicing is the exact
validation layer that turns candidates into trusted cores.

## Proof Sketch: UNSAT Subset Reuse

UNSAT is monotone under conjunction:

\[
C \models \bot \Rightarrow C \land R \models \bot
\]

For a path formula \(\Phi(P)=C\land R\), a certified core \(C\) therefore proves the whole path
infeasible. The core does not need to mention every constraint on the path; it only needs to be a
semantically identical subset of the active path formula.

## Accelerator Validation Boundary

Acceleration and CHTD may produce UNSAT candidates over local bags or reduced formulas. SMT slicing
validates those candidates against exact solver semantics before they enter the certified-core
cache.

Rejected candidates are diagnostic information, not pruning facts. `sat`, `unknown`, timeout, and
solver exceptions reject the candidate for pruning.

## Dense Regions And Abstraction

Some constraint regions are too dense for cheap structural slicing. pysymex can summarize dense
regions only when the summary preserves the relevant satisfiability meaning or is refined through a
CEGAR-style validation loop.

The soundness rule is conservative:

- UNSAT from an exact or validated formula can prune.
- SAT from an abstraction requires concrete validation.
- UNKNOWN or failed refinement cannot prune.

## Complexity Model

The layer targets repeated-work reduction rather than changing worst-case SMT complexity.

| Mechanism | Cost effect |
|---|---|
| Incremental prefix sync | Avoids rebuilding long common prefixes. |
| Dependency slicing | Reduces query size when constraints are independent. |
| AST translation cache | Avoids repeated Python-to-Z3 conversion. |
| Core containment check | Converts prior UNSAT proofs into cheap path pruning. |
| Component cache | Reuses independent component results. |
| Adaptive policy | Disables slicing paths that cost more than they save. |

## Telemetry

Telemetry is part of the architecture because unsafe optimism about solver speed can degrade both
performance and diagnostics. Useful counters include:

- sliced query count;
- constraints before and after slicing;
- cache hit and miss rates;
- Z3 time saved or spent;
- UNSAT core reuse count;
- timeout and unknown rates;
- accelerator validation acceptance and rejection.

## Soundness Boundary

SMT slicing remains sound under these conditions:

- SAT is returned from a dependency-closed and semantically valid formula;
- UNSAT used for pruning is exact or certificate-validated;
- translation caches are context-safe;
- unknown, timeout, unsupported theory, and exceptions remain visible;
- abstractions are validated before their SAT answers are trusted;
- core reuse uses context-safe atom identity.

## Related Components

- `pysymex/core/solver/engine.py`
- `pysymex/core/solver/independence.py`
- `pysymex/core/solver/learner.py`
- `pysymex/core/solver/unsat.py`
- `pysymex/core/memory/cow.py`
- `pysymex/core/memory/unsat_core_registry.py`
- `pysymex/execution/executors/core.py`
- `pysymex/accel/evaluator.py`
