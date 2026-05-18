# pysymex contract architecture

**Author:** Yassine Lahyani
**Scope:** symbolic contracts, bytecode-level injection, Z3 verification, and contract-aware
diagnostics

---

## Purpose

A pysymex contract is a symbolic constraint, not only a documentation annotation. Contract clauses
are compiled into Z3 formulas and participate in path feasibility, postcondition checking, logical
audit classification, and contract verification reports.

Within configured exploration and solver budgets, the contract system targets:

- definite violations only when a feasible counterexample exists;
- definite verification only when the negated obligation is UNSAT;
- explicit `UNKNOWN` when solver or modeling limits prevent a definite answer;
- bytecode-level integration so contracts and executed paths share one symbolic state.

## Contract Taxonomy

| Contract kind | Meaning in pysymex |
|---|---|
| `requires` | Preconditions that constrain valid function entry states. |
| `ensures` | Postconditions checked against each return path. |
| `invariant` | State facts that must remain true across configured program points. |
| `loop_invariant` | Loop facts checked for initialization and preservation. |
| `assumes` | External facts accepted as path constraints without creating a proof obligation. |
| `assigns` | Frame conditions describing the memory locations a function may modify. |
| `pure` | Effect contract marking a function as deterministic and side-effect free for symbolic reuse. |

The exported contract API lives under `pysymex/contracts`.

## Symbolic Meaning

Contracts enter the same constraint universe as branch predicates. A precondition \(P\), path
constraint set \(\Phi\), and postcondition \(Q\) are interpreted through satisfiability:

- \(\Phi \land P\) UNSAT means the call is impossible under the current path.
- \(\Phi \land P \land \lnot Q\) SAT means a postcondition counterexample exists.
- \(\Phi \land P \land \lnot Q\) UNSAT means the postcondition holds for the explored symbolic
  state.
- `unknown`, timeout, unsupported expressions, or compiler failure produce inconclusive contract
  results rather than definite success.

## Hoare-Logic Interpretation

pysymex contract verification follows the standard Hoare-triple shape:

\[
\{P\}\ f\ \{Q\}
\]

For a symbolic execution path \(\pi\), let \(WP_\pi(Q)\) be the weakest precondition of that path
with respect to postcondition \(Q\). A path satisfies the contract when:

\[
P \land Path_\pi \Rightarrow Q
\]

Equivalently, pysymex asks Z3 for a counterexample:

\[
P \land Path_\pi \land \lnot Q
\]

If this formula is SAT, the model is a concrete witness for violation. If it is UNSAT, no
counterexample exists for that explored path under the supported model. If Z3 returns unknown, the
truth of the triple is not established.

## Proof Sketch: Postcondition Verification

For a return path with constraints \(\Phi_\pi\) and return expression \(r\), a postcondition
predicate \(Q(result,\vec{x})\) is verified by proving:

\[
\Phi_\pi \Rightarrow Q(r,\vec{x})
\]

By classical refutation:

\[
\Phi_\pi \Rightarrow Q
\quad\text{iff}\quad
\Phi_\pi \land \lnot Q \models \bot
\]

This is why pysymex checks the negated postcondition. A SAT model is not merely a failed proof; it
is an executable witness under the symbolic encoding. An UNKNOWN solver result is neither a proof
nor a witness.

## Injection Model

pysymex ties contract checks to CPython bytecode execution points:

| Execution point | Contract role |
|---|---|
| Function entry | Initial preconditions and refined input constraints. |
| Calls | Callee preconditions and summarized cross-function obligations. |
| Returns | Postconditions over the returned symbolic value. |
| Mutations | Assignment and invariant checks. |
| Loop boundaries | Loop invariant initialization and preservation checks. |

This design avoids a separate source-level interpreter for contracts. The executor observes the
same bytecode state, stack state, locals, and path constraints that drive ordinary symbolic
execution.

## Compiler And Verifier

The contract subsystem separates responsibilities:

| Component | Role |
|---|---|
| `decorators.py` | Attaches contract metadata to Python callables. |
| `types.py` | Owns structured contract, violation, severity, and verification result types. |
| `compiler.py` | Translates supported predicates into Z3 formulas. |
| `injector.py` | Adds preconditions and postconditions to symbolic execution paths. |
| `verifier.py` | Performs direct contract verification and report construction. |
| `quantifiers/` | Handles supported quantified contract forms. |

Compiler failures and unsupported predicates are correctness-significant. They must surface as
unknown or failed verification states, not silent success.

## Assumptions And Soundness

`assumes` clauses are trusted axioms. If \(A\) is an assumption, pysymex reasons over:

\[
\Phi' = \Phi \land A
\]

This is sound relative to the environment model only when the external world actually satisfies
\(A\). The engine can prove properties inside \(\Phi'\), but it cannot prove \(A\) itself unless the
assumption is separately justified by a model or contract.

This creates a conditional guarantee:

\[
Env \models A \land \Phi' \models Q \Rightarrow \Phi_{real} \models Q
\]

If the environment does not satisfy \(A\), conclusions derived from the assumed path space are not
globally valid.

## Cross-Function Semantics

Function summaries let pysymex reason across calls. A caller path can be combined with a callee's
preconditions, postconditions, assumptions, and frame effects. This supports interprocedural
contradiction detection when a produced value and a later required value cannot both hold.

The soundness boundary is the summary's proof status. A summary can narrow future paths only when
its underlying obligations were established under compatible symbolic assumptions.

## Logical Audit Integration

Contract constraints can participate in logical contradiction detection. In default execution,
ordinary UNSAT branch alternatives are path-pruning facts. In explicit logical audit mode, pysymex
reports a contradiction only when the UNSAT core matches a registered rule shape.

This prevents false positives from treating every infeasible branch alternative as a user-facing
bug.

## Effect And Frame Semantics

`assigns` and `pure` contracts describe memory and effect boundaries:

- `assigns` narrows the set of locations a function may mutate and supports alias analysis.
- `pure` permits deterministic symbolic reuse because equivalent symbolic inputs imply equivalent
  symbolic outputs.

These contracts reduce solver and memory-model ambiguity, but they are also trust boundaries. An
incorrect effect contract can hide behavior, so pysymex treats unsupported or contradictory effect
facts explicitly.

## Frame-Condition Proof Obligation

For an `assigns` set \(W\), the frame condition states that every memory location outside \(W\)
keeps its pre-state value:

\[
\forall \ell \notin W,\ Mem_{post}(\ell)=Mem_{pre}(\ell)
\]

This lets alias analysis avoid considering writes outside the declared frame. The obligation is
sound only if the executor can track writes precisely enough to detect violations. Unknown aliasing
or unsupported mutation must therefore remain visible instead of being treated as frame compliance.

## Result Semantics

Contract verification results use typed states:

| State | Meaning |
|---|---|
| `VERIFIED` | No counterexample exists under the supported symbolic model and solver result is definite. |
| `VIOLATED` | A feasible counterexample exists. |
| `UNKNOWN` | The engine could not establish either verification or violation. |
| `UNSUPPORTED` | The contract or path used behavior outside the supported model. |

The architecture rejects ambiguous `None` or boolean-only outcomes for contract trust decisions.

## Related Components

- `pysymex/contracts/decorators.py`
- `pysymex/contracts/compiler.py`
- `pysymex/contracts/injector.py`
- `pysymex/contracts/types.py`
- `pysymex/contracts/verifier.py`
- `pysymex/contracts/quantifiers/`
- `pysymex/execution/executors/verified.py`
- `pysymex/execution/opcodes/common/functions.py`
- `pysymex/execution/opcodes/common/control.py`
