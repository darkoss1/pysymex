---
name: Core Regression Test Generator
description: "Generate high-value regression, property, fuzz, and stress tests from core findings with strict oracle definitions and risk coverage."
argument-hint: "Findings or target files/symbols and preferred test style"
agent: agent
model: "GPT-5 (copilot)"
---
Generate a maintainer-grade test plan and concrete tests for `./pysymex/core` based on provided findings or risky targets.

Task focus:
- Convert known defects, hypotheses, and risk areas into executable tests.
- Maximize bug-catching power, determinism, and long-term maintainability.
- Prioritize tests that prevent silent correctness drift.

Inputs:
- Primary: finding list (recommended) with severity, file, symbol, and trigger.
- Fallback: selected files/symbols in `./pysymex/core`.

Testing strategy requirements:
1. Risk-first prioritization
- Prioritize `Critical` and `High` findings first.
- Map each test to a specific failure mode and expected invariant.

2. Strong oracle design
- Define exact expected behavior, not just "no exception".
- Add invariant checks for state consistency and deterministic outcomes.
- Use differential checks where practical (old/new path or alternate implementation).

3. Test type mix
- Regression tests for known bugs.
- Property-based tests for symbolic/state invariants.
- Fuzz tests for parser/input-heavy boundaries.
- Stress tests for resource and lifecycle behavior.

4. Flake resistance
- Eliminate time/order dependence where possible.
- Control seeds and environment-sensitive factors.
- Make failures diagnosable with focused assertions.

Output format (strict):

# Coverage Matrix
- Finding/Risk -> Test Type -> Files/Symbols -> Priority

# Proposed Tests
For each test include:
- ID: `T-CORE-###`
- Priority: `P0|P1|P2`
- Target: file and symbol
- Failure mode addressed
- Oracle/invariant definition
- Test data strategy (examples, generators, corpus, fuzz seed)
- Expected runtime class: `fast|moderate|slow`

# Test Code
- Provide concrete test code aligned to existing project style.
- Place tests in appropriate test files with clear names.
- Include fixtures/utilities only when necessary.

# Execution Plan
- Exact command(s) to run just the new tests.
- Full-suite command(s) for confidence checks.
- Notes on quarantining or marking slow tests if needed.

# Gaps and Next Tests
- Remaining uncovered risk areas.
- Highest-value next test additions.

Constraints:
- If repository conventions are unclear, infer from nearby tests and state assumptions.
- Prefer minimal, composable tests over huge scenario scripts.
- Do not invent behavior; tie expectations to observed contracts or explicit assumptions.
- When a finding is uncertain, generate hypothesis-validating tests and label them clearly.

Default behavior:
- If no findings are supplied, inspect `./pysymex/core` and generate a prioritized test backlog plus initial code for top risks.
