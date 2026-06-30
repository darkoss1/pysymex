# Limits

Host analysis limits are elective user guardrails. Automatic mode has no numeric default for
paths, symbolic depth, VM iterations, wall time, or host memory growth. When a configured limit
stops exploration, the analysis is partial and records degradation.

## Host Analysis Limits

Host telemetry tracks paths, depth, iterations, time, memory growth, constraints, solver calls,
and cache activity. Its shared SSoT is `pysymex/_internal/limits`; execution, reporting, and API
error translation all consume that owner. Positive user limits are checked while draining the worklist
and record a stable degraded-pass label when reached. Omitted limits remain telemetry only.

Common labels use the form `resource_limit_<kind>`, such as `resource_limit_time` or
`resource_limit_paths`.

## Sandbox Limits

Sandbox limits are separate. They cap wall time, CPU time, memory, process count, file descriptors,
file size, stdout/stderr size, and serialized result payload size inside the isolation backend.

A sandbox timeout or security violation is not an execution proof. It is a blocked or inconclusive
analysis state.

## Target Resource Analysis

Target-program resource checks are a different domain. `pysymex/analysis/domains/resources`
models resources created by the analyzed program, such as files, locks, sockets, generators, and
context managers. It must not own host execution limits, and `pysymex/limits` must not own
target-resource lifecycle analysis.

## Runtime Configuration Path

Automatic defaults live in `pysymex/_internal/config/defaults.py`. The scanner
and executor accept direct command-line or API values for paths, timeout,
iterations, sandbox use, and cache behavior, then build `ExecutionConfig` and
`ResourceLimits` directly. There is no file-based root config graph in the
current runtime.

## Result Meaning

| State | Meaning |
| --- | --- |
| Limit reached | Exploration stopped before all work was exhausted. |
| Degraded pass | Some behavior was unsupported, inconclusive, or skipped. |
| Sandbox setup error | The requested isolation boundary was not established. |
| Solver UNKNOWN | The encoded query was not solved. |
| Empty issue list with degradation | No definite issue was reported, but the analysis was partial. |

## Evidence In Source

- Defaults: `pysymex/_internal/config/defaults.py`
- Runtime config objects: `pysymex/_internal/config/execution`,
  `pysymex/_internal/config/sandbox`, `pysymex/_internal/config/tracing`
- Host limit models, mapping, probes, and tracker: `pysymex/_internal/limits`
- Execution limit recording: `pysymex/_internal/execution/resources`
- Target resource lifecycle analysis: `pysymex/_internal/analysis/detectors/specialized/resources.py`
- Sandbox resource limits: `pysymex/_internal/sandbox/types.py`
- Tests: `tests/unit/limits`, `tests/unit/execution/resources`,
  `tests/unit/analysis/domains/resources`, `tests/unit/sandbox`

## Explicit Overrides

Adding or increasing a user limit can change coverage and resource use. It does not change
unsupported semantics into supported semantics, and reaching it never becomes a proof of safety.
