"""Centralised hard-limit constants for the pysymex engine.

Every security, resource, and cache bound lives in this single module so
that ``security.py``, ``resources.py``, ``config.py``, and the rest of the
codebase all reference the same canonical values.
"""

from __future__ import annotations

from typing import Final

MAX_PATHS: Final[int] = 100_000
MAX_DEPTH: Final[int] = 1_000
MAX_ITERATIONS: Final[int] = 1_000_000
MAX_TIMEOUT: Final[float] = 3_600.0
MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024
MAX_CODE_SIZE: Final[int] = 1 * 1024 * 1024

FORBIDDEN_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "..",
    "~",
    "\\\\",
)

DANGEROUS_BUILTINS: Final[tuple[str, ...]] = (
    "open",
    "exec",
    "eval",
    "compile",
    "__import__",
    "input",
    "breakpoint",
)

SANDBOX_IMPORT_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "math",
        "typing",
        "collections",
        "itertools",
        "functools",
        "dataclasses",
        "enum",
        "abc",
        "operator",
        "re",
        "string",
        "decimal",
        "fractions",
        "statistics",
        "copy",
        "types",
    }
)

FROM_CONST_CACHE_LIMIT: Final[int] = 512
SYMBOLIC_CACHE_LIMIT: Final[int] = 1024
INSTRUCTION_CACHE_LIMIT: Final[int] = 2048

HMAC_KEY_SIZE: Final[int] = 32
HMAC_DIGEST: Final[str] = "sha256"
HMAC_TAG_SIZE: Final[int] = 32

__all__ = [
    "DANGEROUS_BUILTINS",
    "FORBIDDEN_PATH_PATTERNS",
    "FROM_CONST_CACHE_LIMIT",
    "HMAC_DIGEST",
    "HMAC_KEY_SIZE",
    "HMAC_TAG_SIZE",
    "INSTRUCTION_CACHE_LIMIT",
    "MAX_CODE_SIZE",
    "MAX_DEPTH",
    "MAX_FILE_SIZE",
    "MAX_ITERATIONS",
    "MAX_PATHS",
    "MAX_TIMEOUT",
    "SANDBOX_IMPORT_ALLOWLIST",
    "SYMBOLIC_CACHE_LIMIT",
]
