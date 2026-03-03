"""Security utilities for pysymex.

This module provides security hardening for the analyzer including:
- Path traversal prevention
- Input bounds validation
- Sandboxed code execution
- Resource limits
"""

from __future__ import annotations


import signal

import sys

import threading

from collections.abc import Generator

from contextlib import contextmanager

from dataclasses import dataclass

from pathlib import Path

from typing import Any

try:
    import resource

    HAS_RESOURCE = True

except ImportError:
    HAS_RESOURCE = False

MAX_PATHS = 100000

MAX_DEPTH = 1000

MAX_ITERATIONS = 1000000

MAX_TIMEOUT = 3600

MAX_FILE_SIZE = 10 * 1024 * 1024

MAX_CODE_SIZE = 1 * 1024 * 1024


FORBIDDEN_PATH_PATTERNS = [
    "..",
    "~",
    "\\\\",
]


DANGEROUS_BUILTINS = [
    "open",
    "exec",
    "eval",
    "compile",
    "__import__",
    "input",
    "breakpoint",
]


class SecurityError(Exception):
    """Raised when a security check fails."""

    pass


class PathTraversalError(SecurityError):
    """Raised when a path traversal attack is detected."""

    pass


class ResourceLimitError(SecurityError):
    """Raised when resource limits are exceeded."""

    pass


@dataclass
class SecurityConfig:
    """Configuration for security controls."""

    allow_absolute_paths: bool = True

    allow_symlinks: bool = False

    allowed_directories: list[str] | None = None

    max_memory_mb: int = 512

    max_cpu_seconds: int = 60

    sandbox_builtins: bool = True

    allow_file_io: bool = False

    allow_network: bool = False


def validate_path(
    path: str | Path,
    *,
    must_exist: bool = True,
    must_be_file: bool = True,
    allowed_extensions: list[str] | None = None,
    base_directory: str | Path | None = None,
) -> Path:
    """Validate a file path for safety.

    Args:
        path: The path to validate
        must_exist: Whether the path must exist
        must_be_file: Whether the path must be a file (not directory)
        allowed_extensions: Allowed file extensions (e.g. [".py"])
        base_directory: If provided, path must be within this directory

    Returns:
        Validated absolute Path object

    Raises:
        PathTraversalError: If path contains traversal patterns
        SecurityError: If other validation fails
        FileNotFoundError: If must_exist and path doesn't exist
    """

    path = Path(path)

    path_str = str(path)

    for pattern in FORBIDDEN_PATH_PATTERNS:
        if pattern in path_str:
            raise PathTraversalError(f"Path contains forbidden pattern '{pattern}': {path}")

    resolved = path.resolve()

    base: Path | None = None

    if base_directory is not None:
        base = Path(base_directory).resolve()

        try:
            resolved.relative_to(base)

        except ValueError as exc:
            raise PathTraversalError(
                f"Path escapes base directory: {path} is not within {base}"
            ) from exc

    if path.is_symlink():
        target = path.resolve()

        if base_directory and not str(target).startswith(str(base)):
            raise PathTraversalError(f"Symlink target escapes base: {path}")

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {resolved}")

    if must_be_file and resolved.exists() and not resolved.is_file():
        raise SecurityError(f"Path is not a file: {resolved}")

    if allowed_extensions is not None:
        if resolved.suffix.lower() not in [e.lower() for e in allowed_extensions]:
            raise SecurityError(
                f"File extension not allowed: {resolved.suffix}. Allowed: {allowed_extensions}"
            )

    if resolved.exists() and resolved.is_file():
        size = resolved.stat().st_size

        if size > MAX_FILE_SIZE:
            raise ResourceLimitError(f"File too large: {size} bytes (max: {MAX_FILE_SIZE})")

    return resolved


def validate_bounds(
    value: int,
    name: str,
    min_value: int = 0,
    max_value: int | None = None,
) -> int:
    """Validate an integer is within bounds.

    Args:
        value: The value to validate
        name: Name of the parameter (for error messages)
        min_value: Minimum allowed value
        max_value: Maximum allowed value

    Returns:
        The validated value

    Raises:
        ValueError: If value is out of bounds
    """

    if value < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {value}")

    if max_value is not None and value > max_value:
        raise ValueError(f"{name} must be <= {max_value}, got {value}")

    return value


def validate_config(
    max_paths: int = 1000,
    max_depth: int = 100,
    max_iterations: int = 10000,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Validate execution configuration parameters.

    Returns validated configuration dict with clamped values.
    """

    return {
        "max_paths": validate_bounds(max_paths, "max_paths", 1, MAX_PATHS),
        "max_depth": validate_bounds(max_depth, "max_depth", 1, MAX_DEPTH),
        "max_iterations": validate_bounds(max_iterations, "max_iterations", 1, MAX_ITERATIONS),
        "timeout": min(max(0.1, timeout), MAX_TIMEOUT),
    }


def get_safe_builtins() -> dict[str, Any]:
    """Get a dict of safe builtins for sandboxed execution.

    Removes dangerous functions that could escape the sandbox.
    """

    import builtins

    safe: dict[str, Any] = {}

    for name in dir(builtins):
        if name.startswith("_"):
            continue

        if name in DANGEROUS_BUILTINS:
            continue

        safe[name] = getattr(builtins, name)

    def disabled_builtin(*args: Any, **kwargs: Any) -> None:
        raise SecurityError("This builtin is disabled in sandbox mode")

    for name in DANGEROUS_BUILTINS:
        safe[name] = disabled_builtin

    return safe


def create_sandbox_namespace(
    allow_builtins: bool = True,
    extra_globals: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a sandboxed namespace for code execution.

    Args:
        allow_builtins: Whether to include (safe) builtins
        extra_globals: Additional globals to include

    Returns:
        Namespace dict for use with exec()
    """

    namespace: dict[str, Any] = {}

    if allow_builtins:
        namespace["__builtins__"] = get_safe_builtins()

    else:
        namespace["__builtins__"] = {}

    if extra_globals:
        namespace.update(extra_globals)

    return namespace


class ExecutionTimeout(SecurityError):
    """Raised when execution times out."""

    pass


@contextmanager
def timeout_context(seconds: float) -> Generator[None, None, None]:
    """Context manager that raises ExecutionTimeout after specified seconds.

    On Unix, uses SIGALRM for precise timing.
    On Windows, uses a daemon thread that interrupts the main thread.
    """

    if sys.platform == "win32":
        timed_out = threading.Event()

        def _interrupt() -> None:
            timed_out.set()

            import ctypes

            ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(threading.main_thread().ident),
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

    def handler(_signum: int, frame: Any) -> None:
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

    soft, hard = resource.getrlimit(resource.RLIMIT_AS)

    memory_bytes = max_memory_mb * 1024 * 1024

    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, hard))

    cpu_soft, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)

    resource.setrlimit(resource.RLIMIT_CPU, (max_cpu_seconds, cpu_hard))

    try:
        yield

    finally:
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

        resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft, cpu_hard))


def safe_exec(
    code: str,
    namespace: dict[str, Any] | None = None,
    *,
    timeout_seconds: float = 30.0,
    max_memory_mb: int = 256,
) -> dict[str, Any]:
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

    if namespace is None:
        namespace = create_sandbox_namespace()

    else:
        if "__builtins__" not in namespace:
            namespace["__builtins__"] = get_safe_builtins()

    compiled = compile(code, "<sandbox>", "exec")

    with resource_limits(max_memory_mb):
        with timeout_context(timeout_seconds):
            exec(compiled, namespace)

    return namespace


def sanitize_function_name(name: str) -> str:
    """Sanitize a function name for safe use.

    Args:
        name: Function name to sanitize

    Returns:
        Sanitized function name

    Raises:
        ValueError: If name is invalid
    """

    if not name.replace("_", "").isalnum():
        raise ValueError(f"Invalid function name: {name}")

    if name[0].isdigit():
        raise ValueError(f"Function name cannot start with digit: {name}")

    import keyword

    if keyword.iskeyword(name):
        raise ValueError(f"Function name is a Python keyword: {name}")

    return name


__all__ = [
    "SecurityError",
    "PathTraversalError",
    "ResourceLimitError",
    "SecurityConfig",
    "validate_path",
    "validate_bounds",
    "validate_config",
    "get_safe_builtins",
    "create_sandbox_namespace",
    "timeout_context",
    "resource_limits",
    "safe_exec",
    "sanitize_function_name",
    "MAX_PATHS",
    "MAX_DEPTH",
    "MAX_ITERATIONS",
    "MAX_TIMEOUT",
    "MAX_FILE_SIZE",
    "MAX_CODE_SIZE",
]
