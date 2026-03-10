---
name: Core Review Standards
description: "Use when reviewing or modifying pysymex core files; enforce strict correctness, safety, architecture, and testability checks."
applyTo: "pysymex/core/**/*.py"
---
# Core Review Standards

Use this instruction whenever changing files under `pysymex/core`.

## Primary Standard
- Optimize for correctness and safety before convenience.
- Treat subtle state bugs and silent behavior drift as release blockers.
- Prefer explicit invariants, deterministic behavior, and narrow contracts.

## Review Priorities (in order)
1. Correctness and invariants
- Verify preconditions/postconditions are explicit.
- Reject implicit assumptions that are not enforced.
- Check edge cases: empty inputs, `None`, NaN/inf, overflow-like growth, and stale state reuse.

2. State and concurrency safety
- Audit shared mutable state, copy-on-write paths, cache invalidation, lifecycle ordering, and shutdown behavior.
- Require thread/process safety rationale where mutable shared objects exist.

3. Security and abuse resistance
- Flag unsafe deserialization/parsing, path misuse, unbounded resource usage, and untrusted-input hazards.
- Include local-tool threat models: malicious repo content, crafted input artifacts, and CI execution contexts.

4. Architecture and maintainability
- Minimize hidden coupling and cyclic dependencies.
- Keep module responsibilities cohesive and interfaces explicit.
- Prefer incremental refactors with compatibility shims over disruptive rewrites.

5. Performance and scalability
- Call out algorithmic hotspots and avoidable copies/allocations.
- Distinguish measured regressions from hypotheses.

## Required Output Style for Reviews
- Report findings first, ordered by severity: `Critical`, `High`, `Medium`, `Low`.
- For each finding include file path, symbol, impact, trigger, and fix strategy.
- Separate confirmed defects from hypotheses.
- If confidence is low, say so explicitly.

## Test Expectations for Core Changes
- Every bug fix requires a targeted regression test.
- Every non-trivial behavior change requires contract tests for old vs new behavior where compatibility matters.
- Add stress/property/fuzz tests for parser/state-machine/symbolic-execution-sensitive paths.
- Include negative tests for misuse and malformed input.

## Release Blockers
- Silent correctness drift in symbolic state/constraints/memory model behavior.
- Data races or unsafe shared mutable state behavior.
- Unbounded resource growth on realistic adversarial inputs.
- Public API behavior changes without migration notes or compatibility handling.
