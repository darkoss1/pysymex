"""
Exception Flow Analysis – Type definitions.

Enums, dataclasses, and constants used by the exception analysis module.
"""

from __future__ import annotations


from dataclasses import dataclass, field

from enum import Enum, auto


class ExceptionWarningKind(Enum):
    """Types of exception warnings."""

    UNCAUGHT_EXCEPTION = auto()

    TOO_BROAD_EXCEPT = auto()

    BARE_EXCEPT = auto()

    EXCEPTION_SWALLOWED = auto()

    EXCEPTION_NOT_LOGGED = auto()

    RERAISE_DIFFERENT_TYPE = auto()

    EMPTY_EXCEPT_BLOCK = auto()

    FINALLY_RETURN = auto()

    EXCEPTION_IN_FINALLY = auto()

    UNREACHABLE_EXCEPT = auto()

    DUPLICATE_EXCEPT = auto()

    WRONG_EXCEPTION_ORDER = auto()


class HandlerIntent(Enum):
    """Classification of exception handler intent."""

    SAFETY_NET = auto()

    SILENCED = auto()

    LOGGED = auto()


KNOWN_CRASHY_APIS: set[str] = {
    "z3",
    "dis",
    "ast",
    "json",
    "yaml",
    "pickle",
    "marshal",
    "ctypes",
    "importlib",
    "subprocess",
    "socket",
    "ssl",
    "sqlite3",
    "xml",
    "html",
    "csv",
    "configparser",
    "compile",
    "exec",
    "eval",
    "struct",
    "zlib",
}


@dataclass
class ExceptionWarning:
    """Warning about exception handling."""

    kind: ExceptionWarningKind

    file: str

    line: int

    message: str

    exception_type: str | None = None

    severity: str = "warning"


@dataclass
class ExceptionHandler:
    """Represents an exception handler."""

    line: int

    exception_types: list[str]

    is_bare: bool = False

    is_empty: bool = False

    has_reraise: bool = False

    has_pass: bool = False

    has_logging: bool = False

    has_return: bool = False

    intent: HandlerIntent = HandlerIntent.SILENCED


@dataclass
class TryBlock:
    """Represents a try-except-finally block."""

    start_line: int

    end_line: int

    handlers: list[ExceptionHandler] = field(default_factory=list[ExceptionHandler])

    has_finally: bool = False

    has_else: bool = False

    raises_in_try: list[str] = field(default_factory=list[str])

    raises_in_finally: bool = False

    returns_in_finally: bool = False
