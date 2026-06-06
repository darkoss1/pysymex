# Contracts

Contracts describe expected behavior as preconditions, postconditions, assumptions, frame
conditions, purity checks, assertions, and class invariants. Contract verification is bounded by
the same symbolic execution and solver limits as the rest of the engine.

## Method

1. Decorators register contract clauses on functions.
2. Contract records compile callable or string predicates into Z3 expressions.
3. Offline verifier methods check preconditions, postconditions, loop invariants, and assertions
   against supplied path constraints.
4. Verified execution wraps the symbolic executor and aggregates runtime contract outcomes,
   arithmetic checks, invariant checks, and degraded-pass evidence.
5. Reports distinguish verified, violated, unknown, unsupported, and unreachable obligations.

## Solver Meaning

Postconditions and assertions are verified by checking whether the negated obligation is UNSAT.
SAT gives a counterexample when a model is available. UNKNOWN and solver failures map to UNKNOWN.
Predicate compilation failures map to UNSUPPORTED.

Precondition checks are different: the verifier checks whether the precondition can be satisfied
under the path constraints. UNSAT means the entry condition is unreachable for that path.

## Current Coverage

Supported in verified execution:

- requires and ensures checks captured through runtime contract hooks;
- class invariant obligations when receiver state can be modeled;
- frame-condition and pure-effect checks over modeled VM write events;
- arithmetic issues projected from symbolic execution results.

Explicitly limited:

- loop invariant enforcement is reported as unsupported in verified execution;
- deep heap equality and external/native side effects are outside the current effect-ledger slice;
- termination proof output is not a general proof object.

## Evidence In Source

- Contract records: `pysymex/contracts/types.py`
- Compiler and solver query layer: `pysymex/contracts/compiler.py`, `pysymex/contracts/solver`
- Offline verifier: `pysymex/contracts/verifier.py`
- Verified executor: `pysymex/execution/executors/verified`
- Tests: `tests/unit/contracts`, `tests/unit/execution/executors/test_verified*.py`

## Limits

Contract results are only as strong as the encoded predicates, explored paths, runtime models, and
solver outcomes. UNKNOWN, timeout, unsupported predicates, unsupported loop invariants, and degraded
execution are not proof of correctness.
