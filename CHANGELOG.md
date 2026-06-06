# Changelog

All notable public changes to pysymex are documented here.

## Unreleased

## v0.1.1a0 > v0.1.1a1 - 2026-06-06

This alpha patch release restores Linux namespace sandbox behavior for the
scanner's sandboxed bytecode extraction path.

### Sandbox

- Fixed Linux root-jail runtime mounting so the chroot can resolve `/bin`,
  `/lib`, and `/lib64` through trusted symlinks while keeping the mounted host
  runtime narrow and read-only.
- Added Python stdlib and multiarch library mounts needed by isolated
  interpreter startup on Linux distributions and hosted toolcache runtimes.
- Verified `python -m pysymex scan <file> --stats` under WSL Linux with the
  `LinuxNamespaceBackend`, filesystem jail, network blocking, and seccomp
  capabilities active.

## v0.1.0a5 > v0.1.1a0 - 2026-06-03

This release advances PySyMex across engine architecture, CPython-compatible
execution semantics, explicit solver uncertainty, native isolation, reporting,
contracts, and benchmark coverage.

### Release Focus

`0.1.1a0` is still an alpha release, but it is a large step toward a more
trustworthy symbolic-execution engine. The main direction was to make PySyMex
more explicit about what it can prove, what it cannot model, and when solver or
sandbox uncertainty prevents a definitive result.

The release does not claim complete formal soundness for Python. It improves the
soundness envelope by preserving unsupported, inconclusive, degraded, timeout,
solver-unknown, and missing-model states instead of treating them as verified
safety or confirmed bugs.

### Architecture and Ownership

- Split large execution, core, scanner, detector, sandbox, contract, and report
  responsibilities into clearer owners with stricter import boundaries.
- Reworked executor startup, request/session handling, result construction,
  detector publication, opcode routing, branch handling, lifecycle reset, and
  fallback-event ownership.
- Reorganized core state, heap/identity ownership, solver engine components,
  constraint initialization, type factories, scalar/container ownership, and
  graph initialization.
- Removed obsolete analysis modes and legacy scheduler surfaces that no longer
  matched the current engine architecture.
- Updated architecture documentation around scanning, sandboxing, models,
  solver behavior, SMT slicing, POLAR/CEGIS, contracts, reports, and limits.

### Soundness and Solver Behavior

- Made solver outcomes more structured across satisfiability checks, model
  extraction, implication checks, property validation, detector feasibility,
  resource checks, type constraints, and schedule searches.
- Kept solver `unknown`, timeout, scoped solver failure, missing model data, and
  optional unsat-core failure from becoming reusable infeasibility evidence.
- Added explicit inconclusive/degraded accounting in proof reports, mutation
  validation, randomized property checks, oracle differential validation,
  resource analysis, concurrency checks, and detector feasibility.
- Improved solver cache behavior for exact literals, interval comparisons,
  unsat-subset reuse, query normalization, branch witnesses, exception metadata,
  runtime detector evidence, and cache pressure compaction.

### Execution Semantics and Models

- Expanded Python 3.11, 3.12, and 3.13 bytecode handling with common opcode
  logic and version-specific handlers.
- Improved call and binding semantics for `NoneType` calls, maybe-None call
  policy, interprocedural argument binding, `CALL_FUNCTION_EX`, positional-only
  parameters, keyword calls, varargs, kwargs, and function summaries.
- Corrected exception matching, invalid exception handler behavior, caught and
  uncaught routing, exception payload preservation, context manager behavior,
  descriptor binding, attribute mutation/deletion, and `super()` handling.
- Expanded builtin, container, and stdlib precision for dictionaries, sets,
  tuples, lists, ranges, iterators, `all()`/`any()`, `sum()`, `min()`/`max()`,
  `sorted()`, `reversed()`, `enumerate()`, `zip()`, `filter()`, strings, bytes,
  bytearray, math, pathlib/os/sys, functools, dataclasses, contextlib, and
  regex-like operations.
- Improved exact string/bytes/bytearray behavior for search, split, trim,
  affix, classification, joins, codecs, translation, construction, mutation,
  copying, reversing, and membership.

### Detectors, Reports, and Reproduction

- Hardened runtime and logical detectors so unsupported witnesses, callback
  failures, missing model evidence, and solver uncertainty do not become
  confirmed issues.
- Improved issue confidence and severity handling for type constraints,
  resource lifecycle findings, concurrency findings, formal validation,
  user exceptions, value errors, index errors, assertion errors, and property
  proofs.
- Preserved scanner issue metadata, trigger text, degraded-pass state,
  value-range filtering, and detector feasibility context across reports.
- Expanded reproduction generation for package imports, absolute target paths,
  default expressions, async functions, constructors, class methods, decorators,
  callable objects, bytes literals, `*args`, `**kwargs`, and positional-only
  parameters.

### Contracts and Formal Verification

- Reworked contract evidence, runtime ownership, offline verifier routing,
  report adapters, `old()` snapshots, effect tracking, class invariants,
  quantifier lowering, and native contract frontends.
- Expanded contract coverage for methods, classmethods, staticmethods,
  constructors, `__new__`, subclass initialization, property setters, custom
  `__setattr__`, global instance methods, and nested methods.
- Kept insufficient contract evidence explicit as inconclusive instead of
  implying a proof.

### POLAR, CEGIS, Scheduling, and Spill

- Replaced stale CHTD/scheduler assumptions with the current POLAR/CEGIS
  frontier model.
- Added shadow/runtime rollout modes, native worklist diagnostics, owner
  certificate gates, no-false-prune coverage, evidence preview gates, and
  opt-in runtime exact pruning.
- Added spill support for identity-preserving primitive values, SMT2
  constraints, detector sidecars, exception roots, runtime metadata, loop
  counters, value tables, havoc telemetry, payload integrity digests, and
  malformed payload handling.
- Added benchmark and telemetry coverage for frontier admission, spill behavior,
  CEGIS decisions, proof certificates, and pressure compaction.

### Native Isolation and Source Loading

- Reworked sandboxed source loading so module and bytecode extraction cross the
  sandbox boundary as serialized data rather than live target objects.
- Added and hardened native isolation paths for Windows AppContainer, Linux
  namespaces/seccomp, and WASM fallback selection.
- Removed the weak subprocess backend and kept OS-native isolation as the
  security boundary.
- Hardened Windows AppContainer runtime staging, immutable runtime cache
  validation, manifest caching, process CWD selection, LPAC/token checks, pipe
  handling, and typed Win32 last-error access.
- Hardened Linux namespace root-jail setup, trusted `unshare` lookup, filename
  validation, runtime mounting, seccomp launcher behavior, and CI resource-denial
  handling.
- Improved Docker-based multi-version test execution, Compose project scoping,
  WSL update prompting, and container cleanup behavior.

### CLI, Tracing, Stats, and Benchmarks

- Removed the legacy `concolic` command and kept `pysymex scan`,
  `pysymex analyze`, and `pysymex scan --reproduce` as the current primary CLI
  surfaces.
- Added multi-format CLI reporting, SARIF/HTML/text improvements, report
  severity mapping, and better structured output routing.
- Fixed scan statistics ownership around path-rate averaging, scan-window
  reset, solver counters, clause metrics, final average memory, and peak memory.
- Added tracing latency telemetry, analyzer filters, solver and step summaries,
  slowest path/opcode reporting, and realtime visualization hooks.
- Added benchmark suites and result documentation for scanner/runtime behavior,
  sandbox loading, POLAR/CEGIS, spill paths, cache policies, and regression
  workloads.

### Known Limits

- `0.1.1a0` remains alpha software.
- Unsupported Python semantics, solver unknowns, solver timeouts, degraded
  precision, incomplete models, path limits, and native-isolation denial remain
  explicit limitations.
- These changes improve correctness and maintainability, but they do not make
  all Python programs formally verified.
