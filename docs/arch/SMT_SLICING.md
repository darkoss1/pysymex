# SMT Slicing

SMT slicing reduces solver query size by keeping only constraints linked to the current query. It is
an optimization. It does not prove feasibility or infeasibility by itself.

## Method

1. The solver receives a path prefix and a query suffix.
2. Exact Boolean truths are removed; exact falsehood immediately gives UNSAT.
3. Short prefixes and already aligned prefixes skip slicing.
4. Larger prefixes are registered with the independence optimizer.
5. The optimizer extracts variables and keeps constraints linked to query variables.
6. Variable-free constraints are retained during dependency filtering.
7. The solver checks the sliced prefix plus suffix.
8. UNKNOWN remains UNKNOWN and is not reusable proof.

## Cache Safety

Slice cache keys are cheap prefilters. Before a cached slice is reused, the live path and query
expressions are compared against the stored expressions. Stale weak references are removed.

Definitive solver-result caches skip UNKNOWN. Exact UNSAT-subset reuse validates hash
multiplicity and structural expression equality before returning UNSAT for a larger query.

## UNSAT Cores

UNSAT core extraction uses Z3 assumption literals to find a sufficient UNSAT subset. The returned
core is not promised to be minimal. SAT, UNKNOWN, translation failure, and solver failure return no
core.

## Evidence In Source

- Query slicing call path: `pysymex/_internal/core/solver/engine/sat.py`
- Independence optimizer: `pysymex/_internal/core/solver/independence`
- Result and subset caches: `pysymex/_internal/core/solver/engine/cache/results.py`
- Exact UNSAT subset validation: `pysymex/_internal/core/solver/engine/cache/unsat/subset/core.py`
- UNSAT core extraction: `pysymex/_internal/core/solver/unsat.py`
- Tests: `tests/unit/core/solver/test_independence.py`, `tests/unit/core/solver/test_unsat.py`

## Limits

Slicing can reduce constraints sent to Z3, but it cannot convert timeout or `UNKNOWN` into proof.
It can also disable itself or its slice cache when measured reduction or cache reuse is too low.
