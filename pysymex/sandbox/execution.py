# pysymex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""In-process execution sandboxing utilities.

This module provides Python-level isolation for code execution within
the same process.  These are **defence-in-depth** measures — they are
NOT a security boundary on their own.  True isolation is provided by
the process-level sandbox backends (Linux namespaces, Windows Job
Objects).

Functions in this module are used by:
    - ``api.py`` / ``cli/commands.py`` for loading user files to extract
      function objects.
    - The harness generator (``sandbox/isolation/_harness.py``) embeds
      equivalent logic that runs *inside* the sandboxed subprocess.

Public API:
    - ``get_safe_builtins()`` — builtins dict with dangerous functions
      replaced by stubs.
    - ``create_sandbox_namespace()`` — exec() namespace with safe
      builtins.
    - ``make_restricted_import()`` — ``__import__`` that only permits
      allowlisted modules.
    - ``safe_exec()`` — compile + AST-check + exec in restricted
      namespace with timeout and resource limits.
    - ``timeout_context()`` — wall-clock timeout via SIGALRM or
      threading.
    - ``resource_limits()`` — rlimit context manager (Unix only).
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import warnings
from collections.abc import Generator
from contextlib import contextmanager
from typing import cast

from pysymex._constants import (
    DANGEROUS_BUILTINS,
    MAX_CODE_SIZE,
    SANDBOX_IMPORT_ALLOWLIST,
)


class ExecutionTimeout(Exception):
    """Raised when execution times out."""

    pass


class SecurityError(Exception):
    """Raised when a security check fails in the in-process sandbox."""

    pass


class ResourceLimitError(SecurityError):
    """Raised when resource limits are exceeded."""

    pass


def get_safe_builtins() -> dict[str, object]:
    """Get a dict of safe builtins for sandboxed execution.

    Removes dangerous functions that could escape the sandbox.
    """
    import builtins

    safe: dict[str, object] = {}
    for name in dir(builtins):
        if name.startswith("_"):
            continue
        if name in DANGEROUS_BUILTINS:
            continue
        safe[name] = getattr(builtins, name)

    def disabled_builtin(*args: object, **kwargs: object) -> None:
        raise SecurityError("This builtin is disabled in sandbox mode")

    for name in DANGEROUS_BUILTINS:
        safe[name] = disabled_builtin

    return safe


def create_sandbox_namespace(
    allow_builtins: bool = True,
    extra_globals: dict[str, object] | None = None,
) -> dict[str, object]:
    """Create a sandboxed namespace for code execution.

    Args:
        allow_builtins: Whether to include (safe) builtins
        extra_globals: Additional globals to include

    Returns:
        Namespace dict for use with exec()
    """
    namespace: dict[str, object] = {}

    if allow_builtins:
        namespace["__builtins__"] = get_safe_builtins()
    else:
        namespace["__builtins__"] = {}

    if extra_globals:
        namespace.update(extra_globals)

    return namespace


def make_restricted_import(
    allowlist: frozenset[str] | None = None,
) -> object:
    """Create a restricted ``__import__`` that only permits allowlisted modules.

    Args:
        allowlist: Set of allowed top-level module names.
            Defaults to ``SANDBOX_IMPORT_ALLOWLIST``.

    Returns:
        A callable suitable for ``namespace["__builtins__"]["__import__"]``.
    """
    import builtins

    permitted = allowlist if allowlist is not None else SANDBOX_IMPORT_ALLOWLIST
    real_import = builtins.__import__

    def _restricted_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        """Restricted import with support for granular submodule allowlisting."""
        top_level = name.split(".", maxsplit=1)[0]
        # Check if the full import path is explicitly allowed
        if name in permitted:
            return real_import(name, globals, locals, fromlist, level)
        # Check if the top-level module is allowed
        if top_level in permitted:
            return real_import(name, globals, locals, fromlist, level)
        raise SecurityError(
            f"Import of '{name}' is not permitted in sandbox mode. "
            f"Allowed modules: {', '.join(sorted(permitted))}"
        )

    return _restricted_import


@contextmanager
def timeout_context(seconds: float) -> Generator[None, None, None]:
    """Context manager that raises ExecutionTimeout after specified seconds.

    On Unix, uses SIGALRM for precise timing.
    On Windows, uses a daemon thread that interrupts the main thread.
    """
    if sys.platform == "win32":
        timed_out = threading.Event()

        def _interrupt() -> None:
            """Interrupt."""
            timed_out.set()

            import ctypes

            ident = threading.main_thread().ident
            if ident is None:
                return
            ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(ident),
                ctypes.py_object(ExecutionTimeout),
            )

        timer = threading.Timer(seconds, _interrupt)
        timer.daemon = True
        timer.start()
        try:
            yield
        finally:
            timer.cancel()
        if timed_out.is_set():
            raise ExecutionTimeout(f"Execution timed out after {seconds} seconds")
        return

    def handler(_signum: int, frame: object) -> None:
        raise ExecutionTimeout(f"Execution timed out after {seconds} seconds")

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


@contextmanager
def resource_limits(
    max_memory_mb: int = 512,
    max_cpu_seconds: int = 60,
) -> Generator[None, None, None]:
    """Context manager that enforces resource limits.

    Works on Unix systems only. On Windows, this is a no-op.
    """
    if sys.platform == "win32":
        yield
        return

    import resource

    def _is_infinity(limit_value: int) -> bool:
        return limit_value == getattr(resource, "RLIM_INFINITY", -1)

    def _current_address_space_bytes() -> int | None:
        try:
            with open("/proc/self/statm", "r", encoding="ascii") as f:
                parts = f.read().strip().split()
            if not parts:
                return None
            pages = int(parts[0])
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            return pages * page_size
        except (OSError, ValueError, AttributeError):
            return None

    as_soft, as_hard = resource.getrlimit(resource.RLIMIT_AS)
    cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)

    memory_limit_set = False
    cpu_limit_set = False

    requested_memory_bytes = max_memory_mb * 1024 * 1024
    current_as = _current_address_space_bytes()
    if current_as is not None:
        requested_memory_bytes = max(requested_memory_bytes, current_as + (64 * 1024 * 1024))
    if not _is_infinity(as_hard):
        requested_memory_bytes = min(requested_memory_bytes, as_hard)

    consumed_cpu_seconds = 0.0
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        consumed_cpu_seconds = float(usage.ru_utime) + float(usage.ru_stime)
    except (AttributeError, OSError, ValueError):
        consumed_cpu_seconds = 0.0

    requested_cpu_seconds = int(consumed_cpu_seconds) + max_cpu_seconds + 1
    if not _is_infinity(cpu_hard):
        requested_cpu_seconds = min(requested_cpu_seconds, cpu_hard)

    try:
        resource.setrlimit(resource.RLIMIT_AS, (requested_memory_bytes, as_hard))
        memory_limit_set = True
    except (OSError, ValueError):
        warnings.warn("Unable to set RLIMIT_AS in resource_limits(); continuing without memory cap")

    try:
        if requested_cpu_seconds > int(consumed_cpu_seconds):
            resource.setrlimit(resource.RLIMIT_CPU, (requested_cpu_seconds, cpu_hard))
            cpu_limit_set = True
        else:
            warnings.warn(
                "Skipping RLIMIT_CPU in resource_limits(); process CPU budget already exhausted"
            )
    except (OSError, ValueError):
        warnings.warn("Unable to set RLIMIT_CPU in resource_limits(); continuing without CPU cap")

    try:
        yield
    finally:
        if memory_limit_set:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (as_soft, as_hard))
            except (OSError, ValueError):
                warnings.warn("Failed to restore RLIMIT_AS after resource_limits()")
        if cpu_limit_set:
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))
            except (OSError, ValueError):
                warnings.warn("Failed to restore RLIMIT_CPU after resource_limits()")


def safe_exec(
    code: str,
    namespace: dict[str, object] | None = None,
    *,
    timeout_seconds: float = 30.0,
    max_memory_mb: int = 256,
) -> dict[str, object]:
    """Execute code in a sandboxed environment.

    Args:
        code: Python source code to execute
        namespace: Initial namespace (will be sandboxed)
        timeout_seconds: Maximum execution time
        max_memory_mb: Maximum memory usage

    Returns:
        The namespace after execution

    Raises:
        SecurityError: If code attempts forbidden operations
        ExecutionTimeout: If execution times out
        SyntaxError: If code has syntax errors
    """
    if len(code) > MAX_CODE_SIZE:
        raise ResourceLimitError(f"Code too large: {len(code)} bytes (max: {MAX_CODE_SIZE})")

    import ast

    tree = ast.parse(code, "<sandbox>", "exec")
    _FORBIDDEN_AST_NODES = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)
    for node in ast.walk(tree):
        if isinstance(node, _FORBIDDEN_AST_NODES):
            raise SecurityError(
                f"Forbidden AST node '{type(node).__name__}' at line {getattr(node, 'lineno', '?')}"
            )

    if namespace is None:
        namespace = create_sandbox_namespace()
    else:
        if "__builtins__" not in namespace:
            namespace["__builtins__"] = get_safe_builtins()

    compiled = compile(tree, "<sandbox>", "exec")

    with resource_limits(max_memory_mb), timeout_context(timeout_seconds):
        exec(compiled, namespace)

    return namespace


def get_hardened_builtins(
    *,
    import_allowlist: frozenset[str] | None = None,
) -> dict[str, object]:
    """Get maximally restricted builtins for hardened in-process execution.

    This uses ``HARDENED_DANGEROUS_BUILTINS`` (the strictest blocklist)
    and replaces ``getattr``/``setattr``/``delattr``/``hasattr`` with
    runtime-guarded versions that block access to dangerous dunder
    attributes regardless of how the name string was constructed.
    """
    import builtins

    from pysymex._constants import HARDENED_DANGEROUS_BUILTINS

    safe: dict[str, object] = {}
    for name in dir(builtins):
        if name.startswith("_"):
            continue
        if name in HARDENED_DANGEROUS_BUILTINS:
            continue
        safe[name] = getattr(builtins, name)

    def disabled_builtin(*args: object, **kwargs: object) -> None:
        raise SecurityError("This builtin is disabled in sandbox mode")

    for name in HARDENED_DANGEROUS_BUILTINS:
        safe[name] = disabled_builtin

    safe["getattr"] = _safe_getattr
    safe["setattr"] = _safe_setattr
    safe["delattr"] = _safe_delattr
    safe["hasattr"] = _safe_hasattr

    safe["__import__"] = make_restricted_import(import_allowlist)

    build_class = getattr(builtins, "__build_class__", None)
    if build_class is not None:
        safe["__build_class__"] = build_class

    return safe


def _check_attr_name(name: str) -> None:
    """Raise if *name* matches a dangerous attribute pattern."""
    from pysymex._constants import DANGEROUS_ATTR_NAMES

    if name in DANGEROUS_ATTR_NAMES:
        raise SecurityError(f"Access to attribute '{name}' is blocked in sandbox mode")


def _safe_getattr(obj: object, name: str, *default: object) -> object:
    """Runtime-guarded ``getattr`` that blocks dangerous attribute names."""
    _check_attr_name(name)
    return getattr(obj, name, *default)


def _safe_setattr(obj: object, name: str, value: object) -> None:
    """Runtime-guarded ``setattr`` that blocks dangerous attribute names."""
    _check_attr_name(name)
    setattr(obj, name, value)


def _safe_delattr(obj: object, name: str) -> None:
    """Runtime-guarded ``delattr`` that blocks dangerous attribute names."""
    _check_attr_name(name)
    delattr(obj, name)


def _safe_hasattr(obj: object, name: str) -> bool:
    """Runtime-guarded ``hasattr`` that blocks dangerous attribute names."""
    _check_attr_name(name)
    return hasattr(obj, name)


def _validate_ast_security(
    tree: object,
    source: str,
    filename: str,
) -> None:
    """Deep AST validation that rejects known sandbox-escape patterns.

    Checks:
        1. Attribute access to dangerous dunder names
        2. Name access to dangerous identifiers (``__builtins__`` etc.)
        3. String literals containing dangerous patterns
        4. ``ast.Global`` / ``ast.Nonlocal`` statements
    """
    import ast

    from pysymex._constants import (
        DANGEROUS_ATTR_NAMES,
        DANGEROUS_STRING_PATTERNS,
    )

    dangerous_names: frozenset[str] = frozenset(
        {"__builtins__", "__loader__", "__spec__", "__import__"}
    )

    for node in ast.walk(cast("ast.AST", tree)):  # type: ignore[arg-type]  # tree is AST but inferred as object
        if isinstance(node, ast.Attribute):
            if node.attr in DANGEROUS_ATTR_NAMES:
                lineno = getattr(node, "lineno", "?")
                raise SecurityError(
                    f"Blocked attribute access '{node.attr}' at "
                    f"{filename}:{lineno} — sandbox escape vector"
                )

        elif isinstance(node, ast.Name):
            if node.id in dangerous_names:
                lineno = getattr(node, "lineno", "?")
                raise SecurityError(
                    f"Blocked name access '{node.id}' at "
                    f"{filename}:{lineno} — sandbox escape vector"
                )

        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            for pattern in DANGEROUS_STRING_PATTERNS:
                if pattern in node.value:
                    lineno = getattr(node, "lineno", "?")
                    raise SecurityError(
                        f"Blocked string literal containing '{pattern}' at "
                        f"{filename}:{lineno} — potential sandbox escape"
                    )

        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            lineno = getattr(node, "lineno", "?")
            raise SecurityError(
                f"Blocked '{type(node).__name__}' statement at "
                f"{filename}:{lineno} — scope manipulation"
            )


def hardened_exec(
    source: str,
    filename: str,
    *,
    extra_globals: dict[str, object] | None = None,
    import_allowlist: frozenset[str] | None = None,
) -> dict[str, object]:
    """Execute source code in a maximally hardened in-process sandbox.

    This is the strictest in-process execution mode, combining:

    1. **AST validation** — rejects dangerous attribute access,
       suspicious string literals, and scope manipulation statements.
    2. **Hardened builtins** — ``globals()``, ``locals()``, ``vars()``,
       ``dir()``, ``type()``, ``memoryview`` etc. are all disabled.
    3. **Runtime-guarded attribute access** — ``getattr``/``setattr``/
       ``delattr``/``hasattr`` are replaced with wrappers that block
       dangerous attribute names at runtime (catches string-concatenation
       bypasses that static AST analysis cannot detect).
    4. **Restricted imports** — only allowlisted stdlib modules.
    5. **Code size limit** — prevents resource exhaustion.

    Args:
        source: Python source code to execute.
        filename: Filename for error messages and code object.
        extra_globals: Additional globals to inject into the namespace.
        import_allowlist: Override the default import allowlist.

    Returns:
        The namespace after execution (contains defined functions, etc.).

    Raises:
        SecurityError: If any security check fails.
        SyntaxError: If source has syntax errors.
    """
    import ast

    from pysymex._constants import MAX_CODE_SIZE

    if len(source.encode("utf-8")) > MAX_CODE_SIZE:
        raise ResourceLimitError(
            f"Source too large: {len(source)} chars (max: {MAX_CODE_SIZE} bytes)"
        )

    tree = ast.parse(source, filename, "exec")
    _validate_ast_security(tree, source, filename)

    hardened_builtins = get_hardened_builtins(import_allowlist=import_allowlist)
    namespace: dict[str, object] = {
        "__builtins__": hardened_builtins,
        "__name__": "__main__",
        "__file__": filename,
    }
    if extra_globals:
        namespace.update(extra_globals)

    compiled = compile(tree, filename, "exec")
    exec(compiled, namespace)

    return namespace


__all__ = [
    "ExecutionTimeout",
    "ResourceLimitError",
    "SecurityError",
    "create_sandbox_namespace",
    "get_hardened_builtins",
    "get_safe_builtins",
    "hardened_exec",
    "make_restricted_import",
    "resource_limits",
    "safe_exec",
    "timeout_context",
]
