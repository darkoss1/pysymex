# pysymex sandbox architecture

**Author:** Yassine Lahyani
**Scope:** filesystem containment, restricted imports, process isolation, and analysis safety

---

## Purpose

pysymex executes and inspects untrusted or semi-trusted Python code during analysis. The sandbox
architecture reduces the risk of host mutation, import escape, subprocess abuse, and resource
exhaustion.

The sandbox is defense in depth. Python-level restrictions are useful, but the strongest boundary is
the process-level isolation backend when the host platform supports it.

## Security Model

Let \(H\) be the host state and \(S\) be the sandbox state. A sandbox execution is contained when
observable writes are restricted to the sandbox authority set \(A_S\):

\[
WriteSet(exec) \subseteq A_S
\]

For filesystem staging, the authority set is the resolved sandbox root:

\[
A_S = \{p \mid resolved(p)\ \text{is under}\ resolved(root)\}
\]

The containment property is semantic, not merely lexical. A path string can appear relative while
resolving outside the sandbox through symlinks, drive prefixes, or platform normalization.

## Threat Model

The sandbox is designed around these risks:

- path traversal in staged analysis inputs;
- absolute-path or Windows drive-prefix escapes;
- host overwrite through symlink or resolved-path redirection;
- import of unsafe modules from analyzed code;
- dangerous builtins during in-process loading;
- resource exhaustion through CPU, memory, or subprocess behavior;
- unsupported host isolation capabilities being mistaken for strict isolation.

## Architecture Layers

| Layer | Role |
|---|---|
| Safe builtins | Removes or replaces builtins that can directly escape the analysis namespace. |
| Restricted imports | Allows only configured modules and approved restricted proxies. |
| AST and code-size checks | Rejects code shapes outside the sandbox policy before execution. |
| Filesystem staging | Copies extra files only through validated relative paths. |
| Resolved-path containment | Verifies final write targets remain under the sandbox root. |
| Process backend | Applies host isolation such as Windows Job Objects or platform-specific subprocess controls. |
| Resource limits | Bounds CPU, memory, timeout, and cleanup behavior where supported. |

## Filesystem Boundary

Sandbox staging treats user-provided file paths as untrusted data. Paths are accepted only when they
remain relative to the sandbox root and do not contain traversal or command-like leading segments.

Resolved-path containment is required because lexical checks alone do not protect against symlinks
or platform-specific path normalization behavior.

## Proof Sketch: Resolved-Path Containment

Let \(root\) be the resolved sandbox root and \(target\) the resolved destination path. The sandbox
permits a write only when:

\[
target \in subtree(root)
\]

If a user supplies a traversal path, absolute path, drive-prefixed path, or symlink path that
resolves outside \(root\), then:

\[
target \notin subtree(root)
\]

and the write is denied. Therefore every permitted staged write remains inside sandbox authority,
assuming the resolution check and the write target refer to the same filesystem object at the time
of use.

## Import Boundary

pysymex uses an allowlisted import model for sandboxed execution. The import boundary is explicit:
modules outside the allowlist raise a sandbox security error instead of being imported and later
ignored.

Some modules may be represented by restricted proxies when the engine needs a narrow safe surface
for verification internals.

## Import Authority

The import allowlist defines a module authority set \(M\). A sandbox import request for module \(m\)
is permitted only when:

\[
m \in M
\]

or when a restricted proxy \(p_m\) exposes a strict subset of the original module's authority:

\[
Authority(p_m) \subset Authority(m)
\]

This subset relation is why restricted proxies are safer than importing full modules for narrow
engine internals.

## Backend Capability Boundary

Sandbox backend selection must reflect actual host capabilities. If a strict backend is not
available, pysymex degrades visibly instead of pretending strict isolation is active.

On Windows, Job Object controls provide process containment and memory-limit enforcement where
available. Compatibility fallback behavior is part of the boundary because different hosts reject
different flag combinations.

## Diagnostics

Sandbox failures are correctness-significant. A denied import, blocked filesystem write, resource
limit, or unavailable strict backend can affect what code was analyzed. Those states must remain
visible to diagnostics rather than being converted into ordinary success.

## Soundness Boundary

Sandboxing does not prove analyzed code is safe. It protects the analysis host and preserves
diagnostic honesty. The boundary is:

\[
\text{Denied operation} \Rightarrow \text{analysis may be incomplete}
\]

not:

\[
\text{Denied operation} \Rightarrow \text{target program is bug-free}
\]

This distinction matters because sandbox denials can hide paths that would otherwise execute.

## Related Components

- `pysymex/sandbox/`
- `pysymex/sandbox/execution.py`
- `pysymex/sandbox/isolation/`
- `pysymex/_constants.py`
