# Scanning

Scanning turns source files into symbolic-execution jobs and normalized `ScanResult` records. It
does not execute target module top-level code merely to discover globals.

## Method

1. File and directory entry points normalize paths and select target files.
2. Type-hint extraction reads the source AST.
3. Source scan paths select code objects that come from the target source.
4. Sandbox bytecode extraction is used by default for file scans.
5. Compile-only loading builds module globals from declarations and safe imported values.
6. Symbolic execution runs over functions and class methods selected for scanning.
7. Preflight checks add source-level diagnostics for specific static patterns.
8. Scanner issue records are deduplicated and stored in `ScanResult`.

Directory scans choose sequential or parallel execution from the requested worker count, file count,
trace settings, and sandbox mode. On Windows, sequential scans can reuse a scoped sandbox bytecode
session so repeated extraction does not repeatedly set up the backend.

## Compile-Only Globals

The loading layer binds top-level classes and functions, discovers package context, and populates a
small default global environment. It is designed to avoid running target module bodies before
symbolic analysis. That keeps import-time side effects out of the normal scan path.

Safe standard-library imports can be populated concretely when the loading layer recognizes them.
Dynamic imports, native modules, reflection-heavy globals, and arbitrary top-level execution remain
outside this guarantee.

## Sandbox Bytecode Bridge

When sandboxing is enabled, the scanner asks the sandbox bridge to compile source bytes inside the
configured isolation backend. The worker serializes bounded code-object metadata and the host
reconstructs a code object from a validated payload.

The host rejects payloads without the dynamic marker, payloads above the configured result limit,
non-CPython producers, unexpected schema fields, malformed bytecode, and oversized constants.

## Result Meaning

`ScanResult` records issues, code-object count, explored paths, elapsed time, memory, fatal errors,
degraded passes, and solver statistics. A result with no issues but with `error` or
`degraded_passes` is not a clean verification result.

## Evidence In Source

- Single-file scan: `pysymex/scanner/file.py`
- Directory scan: `pysymex/scanner/directory`
- Compile-only loading: `pysymex/analysis/scan/loading`
- Bytecode bridge: `pysymex/sandbox/bridge`
- Issue sink and result types: `pysymex/scanner/issue_sink.py`, `pysymex/scanner/types.py`
- Tests: `tests/unit/scanner`, `tests/unit/sandbox/test_bridge_bytecode.py`

## Limits

Scanning can miss behavior that depends on unsupported imports, unsupported runtime models, bounded
path exploration, sandbox setup failure, solver `UNKNOWN`, or disabled detectors. Those states must
be reported as errors or degraded analysis rather than hidden behind a clean issue list.
