---
name: Core Maintainer Audit
description: "Deeply audit pysymex core for correctness, security, architecture, and performance; produce a strict maintainer-grade improvement roadmap."
argument-hint: "Target path and constraints (default: ./pysymex/core)"
agent: agent
model: "GPT-5 (copilot)"
---
Perform a maximum-effort, high-precision engineering audit of the target module (default: `./pysymex/core`).

Primary objective:
- Reach maintainer-grade confidence in correctness, safety, architecture, and operability.
- Identify flaws, vulnerabilities, hidden coupling, and inefficiencies.
- Produce an actionable plan to move quality toward standards expected from mature libraries (e.g., requests-level maintenance rigor).

Operating mode:
- Be exhaustive, skeptical, and evidence-driven.
- Prefer concrete findings over generic advice.
- Trace effects across module boundaries when needed (imports, call sites, shared state, exception flows, public API usage).
- Assume this is a local developer tool, but still treat misuse, unsafe defaults, and data loss risks as real.
- Do not stop at style feedback; focus on behavior, reliability, and maintainability.

Required analysis dimensions:
1. Correctness and logic safety
- Find potential bugs, edge-case failures, undefined behavior, state corruption, and non-determinism.
- Highlight assumptions that are not enforced.

2. Security and abuse resistance
- Identify unsafe parsing, injection surfaces, resource exhaustion risks, insecure temp/file handling, unsafe eval/exec, untrusted input hazards, race conditions, and path handling problems.
- Note realistic threat models for local tools (malicious input files, poisoned repositories, CI context, shared machines).

3. Architecture and boundaries
- Evaluate module responsibilities, cohesion/coupling, layering, cyclic dependencies, and API contract clarity.
- Find places where architecture increases bug probability.

4. Performance and scalability
- Spot algorithmic hotspots, unnecessary allocations/copies, lock contention, cache misuse, N^2 patterns, and avoidable solver/model overhead.
- Distinguish measured bottlenecks from hypotheses.

5. Concurrency and state model
- Inspect thread/process safety, shared mutable state, copy-on-write semantics, lifecycle/shutdown behavior, and reentrancy hazards.

6. Testing and verification quality
- Map risks to test coverage gaps.
- Propose high-value tests: regression, property-based, fuzz, differential, and stress tests.

Output format (strict):

# Executive Risk Summary
- Overall confidence score (0-100)
- Highest-risk subsystem(s)
- Release-blocker count

# Findings (Ordered by Severity)
For each finding, include:
- ID: `CORE-###`
- Severity: `Critical|High|Medium|Low`
- Confidence: `High|Medium|Low`
- Location: specific file path(s) and function/class names
- Evidence: concrete explanation tied to observed code behavior
- Impact: what can break and in which scenarios
- Exploitability/Trigger: realistic trigger conditions
- Recommended fix: precise change strategy
- Verification: exact test(s) needed to prove fix

# Architecture Improvement Plan
- 30/60/90 day roadmap
- Refactor sequence with dependency order
- Backward-compatibility strategy for public interfaces
- Migration risks and mitigations

# Quality Gates (Must Pass)
Define strict gates before claiming "stable":
- Static analysis / type safety targets
- Test reliability and coverage thresholds by risk area
- Performance budget and regression thresholds
- Security checks and abuse-case tests
- Observability/logging/error-contract requirements

# Maintainer Checklist
- Ongoing practices to sustain quality at mature-library level
- Code review checklist tailored to this module
- Release checklist for safe iteration

Constraints:
- If uncertain, say so and reduce confidence instead of guessing.
- Separate confirmed issues from hypotheses.
- Prefer small, composable refactors over risky rewrites unless rewrite is justified.
- When recommending major changes, include a minimally disruptive transition path.

Invocation context:
- If the user provides selected files/symbols, prioritize them first.
- If no target is provided, audit `./pysymex/core` recursively.
