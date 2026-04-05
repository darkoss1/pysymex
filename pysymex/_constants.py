# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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


SANDBOX_BLOCKED_MODULES: Final[frozenset[str]] = frozenset(
    {
        "socket",
        "_socket",
        "ssl",
        "_ssl",
        "urllib",
        "http",
        "ftplib",
        "smtplib",
        "telnetlib",
        "poplib",
        "imaplib",
        "nntplib",
        "xmlrpc",
        "socketserver",
        "webbrowser",
        "antigravity",
        "subprocess",
        "_posixsubprocess",
        "multiprocessing",
        "concurrent",
        "ctypes",
        "_ctypes",
        "cffi",
        "shutil",
        "pickle",
        "_pickle",
        "shelve",
        "code",
        "codeop",
        "compileall",
        "py_compile",
        "pty",
        "termios",
        "winreg",
        "_winreg",
        "win32api",
        "win32con",
        "win32process",
        "win32security",
        "wmi",
        "_winapi",
        "msvcrt",
        "signal",
    }
)

SANDBOX_DANGEROUS_BUILTINS: Final[frozenset[str]] = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
        "exit",
        "quit",
        "help",
        "memoryview",
        "globals",
        "locals",
        "vars",
    }
)

SANDBOX_SUSPICIOUS_PATTERNS: Final[tuple[str, ...]] = (
    "__subclasses__",
    "__globals__",
    "__bases__",
    "__mro__",
    "__builtins__",
    "__loader__",
    "__spec__",
    "__import__",
    "_io.FileIO",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "importlib",
    "codecs.open",
)


HARDENED_DANGEROUS_BUILTINS: Final[frozenset[str]] = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "open",
        "input",
        "breakpoint",
        "exit",
        "quit",
        "globals",
        "locals",
        "vars",
        "dir",
        "help",
        "memoryview",
        "type",
    }
)

DANGEROUS_ATTR_NAMES: Final[frozenset[str]] = frozenset(
    {
        "__subclasses__",
        "__bases__",
        "__mro__",
        "__globals__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__code__",
        "__closure__",
        "__func__",
        "__self__",
        "__wrapped__",
        "__getattribute__",
        "__reduce__",
        "__reduce_ex__",
        "__traceback__",
        "tb_frame",
        "f_globals",
        "f_locals",
        "f_code",
        "f_builtins",
        "f_back",
        "gi_frame",
        "gi_code",
        "cr_frame",
        "cr_code",
        "ag_frame",
        "ag_code",
    }
)

DANGEROUS_STRING_PATTERNS: Final[frozenset[str]] = frozenset(
    {
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__loader__",
        "__spec__",
        "__code__",
        "__closure__",
        "__import__",
        "__getattribute__",
        "__reduce__",
        "__reduce_ex__",
        "f_globals",
        "f_locals",
        "f_builtins",
        "f_back",
        "tb_frame",
        "_io.FileIO",
        "os.system",
        "os.popen",
        "os.exec",
        "os.spawn",
        "importlib",
        "codecs.open",
        "subprocess",
    }
)

__all__ = [
    "DANGEROUS_ATTR_NAMES",
    "DANGEROUS_BUILTINS",
    "DANGEROUS_STRING_PATTERNS",
    "FORBIDDEN_PATH_PATTERNS",
    "FROM_CONST_CACHE_LIMIT",
    "HARDENED_DANGEROUS_BUILTINS",
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
    "SANDBOX_BLOCKED_MODULES",
    "SANDBOX_DANGEROUS_BUILTINS",
    "SANDBOX_IMPORT_ALLOWLIST",
    "SANDBOX_SUSPICIOUS_PATTERNS",
    "SYMBOLIC_CACHE_LIMIT",
]
