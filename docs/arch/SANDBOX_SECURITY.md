# Sandbox Security Architecture

**pysymex v0.1.0a4 - Sandbox Hardening Reference**

---

## Overview

pysymex includes a hardened sandbox subsystem to contain risky execution paths during analysis workflows.
The sandbox layer focuses on strict filesystem boundaries, backend capability checks, and platform-aware isolation behavior.

## Threat Model

The sandbox is designed to mitigate:

- Path traversal in sandbox file injection inputs.
- Absolute-path and drive-prefix escape attempts.
- Host overwrite via symlink or resolved-path redirection.
- Weak backend selection on unsupported hosts.
- Resource abuse from unbounded memory usage in subprocesses.

## Key Hardening Controls

### 1. Extra File Path Sanitization

Sandbox file staging validates all user-provided relative paths and rejects:

- Absolute paths.
- Drive-prefixed paths on Windows.
- Traversal markers such as `..` segments.
- Dangerous leading `-` path segments.

### 2. Resolved-Path Containment

Before writing staged files, isolation backends verify that resolved output targets remain within the sandbox root.
This prevents host filesystem overwrite through redirection tricks.

### 3. Backend Capability Validation

Runner backend selection validates platform/runtime support before choosing a strict backend.
If unsupported, pysymex falls back safely instead of applying an invalid isolation mode.

### 4. Windows Job Object Enforcement

On Windows, the sandbox applies Job Object controls with memory-limit flags derived from sandbox configuration.
Startup paths include compatibility fallback behavior when strict host policy constraints reject certain flags.

## Validation

Sandbox hardening is validated through adversarial regression tests that cover:

- Escape payload rejection.
- Backend selection and fallback behavior.
- Startup and cleanup behavior on constrained hosts.
- Path containment invariants.

## Related Components

- `pysymex/sandbox/`
- `pysymex/sandbox/isolation/`
