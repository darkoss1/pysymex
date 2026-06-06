# Limits

Limits keep symbolic execution bounded. They are part of the result meaning, not just
configuration. When a limit stops exploration, the analysis is partial.

## Host Analysis Limits

Host limits track paths, depth, iterations, time, memory growth, constraints, solver calls, and
cache activity. The execution loop checks these limits while draining the worklist and records a
stable degraded-pass label when a limit is reached.

Common labels use the form `resource_limit_<kind>`, such as `resource_limit_time` or
`resource_limit_paths`.

## Sandbox Limits

Sandbox limits are separate. They cap wall time, CPU time, memory, process count, file descriptors,
file size, stdout/stderr size, and serialized result payload size inside the isolation backend.

A sandbox timeout or security violation is not an execution proof. It is a blocked or inconclusive
analysis state.

## Configuration Path

Defaults live in the configuration package. User-facing config files load into a top-level config
object, then convert analysis limits into resource limits used by execution.

The scanner and executor also accept direct command-line or API values for paths, timeout,
iterations, sandbox use, deterministic mode, random seed, and cache behavior.

## Result Meaning

| State | Meaning |
| --- | --- |
| Limit reached | Exploration stopped before all work was exhausted. |
| Degraded pass | Some behavior was unsupported, inconclusive, or skipped. |
| Sandbox setup error | The requested isolation boundary was not established. |
| Solver UNKNOWN | The encoded query was not solved. |
| Empty issue list with degradation | No definite issue was reported, but the analysis was partial. |

## Evidence In Source

- Defaults: `pysymex/config/defaults.py`
- Config root and sections: `pysymex/config`
- Host resource tracker: `pysymex/resources`
- Execution limit recording: `pysymex/execution/resources`
- Sandbox resource limits: `pysymex/sandbox/types.py`
- Tests: `tests/unit/execution/resources`, `tests/unit/resources`, `tests/unit/sandbox`

## Limits

Increasing limits can improve coverage, but it can also increase solver time and memory use. It
does not change unsupported semantics into supported semantics.
