# CEGIS

CEGIS is the evidence-selection layer for frontier work. It ranks possible actions, asks the
responsible subsystem to evaluate the chosen action, and applies removals only when exact
certificate gates pass.

## Method

1. Shadow capsules produce evidence bids.
2. The policy selects the highest-scoring sound bid within the active budget.
3. The selected action is evaluated by its subsystem: VM, solver, frontier, or detector.
4. The outcome is typed as executed, SAT, exact UNSAT, exact dominated, inconclusive, unsupported,
   solver unknown, or timeout.
5. A dry-run application plan maps certificate-covered capsule IDs to live state IDs.
6. Runtime application removes states only when the plan is valid.

## No-False-Prune Gates

Queued work may be removed only when all of these are true:

- the selected action is allowed to remove work;
- the action requires exact evidence;
- the outcome is exact UNSAT or exact dominated;
- a certificate is present;
- certificate coverage matches the selected capsule and the removal family;
- the covered capsule IDs are still live.

SAT, solver `UNKNOWN`, timeout, unsupported, inconclusive, missing checkpoint, failed
reconstruction, and invalid coverage are non-removing outcomes.

## Evidence Families

| Family | Evidence |
| --- | --- |
| UNSAT core | Solver establishes UNSAT for a reconstructed checkpoint and returns core indices. |
| Dominance | Frontier checkpoints prove exact structural duplicate coverage. |
| Execute step | VM execution remains a normal non-removing action. |

Automatic proof pruning is currently disabled by a zero frontier limit. Runtime mode can still use
CEGIS to select detector-obligation states for execution and to apply explicit exact outcomes in
tests or callers.

## Evidence In Source

- Runtime controller: `pysymex/execution/scheduling/cegis/runtime.py`
- Bids and policy: `pysymex/execution/scheduling/cegis/bids.py`, `policy.py`
- Outcome typing: `pysymex/execution/scheduling/cegis/outcomes.py`
- Application plan: `pysymex/execution/scheduling/cegis/application.py`
- Evaluators: `pysymex/execution/scheduling/cegis`
- Tests: `tests/unit/execution/scheduling/cegis`, `tests/unit/scanner/test_polar_cegis_no_false_prune.py`

## Limits

CEGIS is not a solver and not a detector. It ranks and routes evidence actions. The exact
subsystem result still decides whether anything can be removed.
