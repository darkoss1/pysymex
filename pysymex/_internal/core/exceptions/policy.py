# pysymex: python symbolic execution & formal verification
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

"""Single source of truth for CPython runtime exception models.

This module owns construction of exceptions that represent target-program
runtime behaviour. Internal engine/configuration errors should still raise
normal Python exceptions directly; modeled CPython exceptions should go through
this policy so type, message, source position, confidence, and issue mapping do
not drift across opcode handlers and stdlib models.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import get_position_column, get_position_line, get_starts_line
from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.exceptions.builtins import BUILTIN_EXCEPTIONS
from pysymex._internal.core.exceptions.categories import ExceptionCategory, get_exception_category
from pysymex._internal.core.exceptions.objects import SymbolicException
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState

ExceptionType = type[BaseException] | str

_BUILTIN_EXCEPTION_BY_NAME: dict[str, type[BaseException]] = {
    exc_type.__name__: exc_type for exc_type in BUILTIN_EXCEPTIONS
}

_RUNTIME_ISSUE_KIND_BY_EXCEPTION_NAME: dict[str, IssueKind] = {
    "AttributeError": IssueKind.ATTRIBUTE_ERROR,
    "IndexError": IssueKind.INDEX_ERROR,
    "KeyError": IssueKind.KEY_ERROR,
    "OverflowError": IssueKind.OVERFLOW,
    "TypeError": IssueKind.TYPE_ERROR,
    "ValueError": IssueKind.VALUE_ERROR,
    "ZeroDivisionError": IssueKind.DIVISION_BY_ZERO,
}


@dataclass(frozen=True, slots=True)
class ModeledRuntimeException(SymbolicException):
    """Runtime exception payload with detector confidence metadata."""

    confidence: float = 1.0
    likelihood: float = 1.0

    @property
    def name(self) -> str:
        """Return the exception type name used by handler routing."""
        return self.type_name


def canonical_exception_type(exc_type: ExceptionType) -> ExceptionType:
    """Return a concrete builtin exception class when a known name is supplied."""
    if isinstance(exc_type, str):
        return _BUILTIN_EXCEPTION_BY_NAME.get(exc_type, exc_type)
    return exc_type


def exception_type_name(exc_type: ExceptionType) -> str:
    """Return the CPython-style name for a modeled exception type."""
    canonical = canonical_exception_type(exc_type)
    return canonical.__name__ if isinstance(canonical, type) else str(canonical)


def issue_kind_for_exception(exc_type: ExceptionType, message: str | None = None) -> IssueKind:
    """Return the detector issue kind for an escaping modeled runtime exception."""
    type_name = exception_type_name(exc_type)
    if type_name == "ZeroDivisionError" and message is not None and "modulo" in message:
        return IssueKind.MODULO_BY_ZERO
    return _RUNTIME_ISSUE_KIND_BY_EXCEPTION_NAME.get(type_name, IssueKind.UNHANDLED_EXCEPTION)


_EXPLICIT_RAISE_ISSUE_KIND_BY_EXCEPTION_NAME: dict[str, IssueKind] = {
    "AttributeError": IssueKind.ATTRIBUTE_ERROR,
    "IndexError": IssueKind.INDEX_ERROR,
    "KeyError": IssueKind.KEY_ERROR,
    "TypeError": IssueKind.TYPE_ERROR,
    "ValueError": IssueKind.VALUE_ERROR,
}


def issue_kind_for_explicit_raise(exc_type: ExceptionType) -> IssueKind:
    """Return issue kind for a user-authored ``raise`` statement.

    Explicitly raising ``ZeroDivisionError`` is not the same signal as a proven
    division opcode with a zero denominator, so arithmetic/runtime operation
    issues intentionally use :func:`issue_kind_for_exception` instead. Other
    builtins keep their specific issue kind for existing filtering and
    suppression logic; the outcome layer uses the ``user_exception`` detector
    origin to classify them as ``TARGET_EXCEPTION``.
    """
    return _EXPLICIT_RAISE_ISSUE_KIND_BY_EXCEPTION_NAME.get(
        exception_type_name(exc_type),
        IssueKind.UNHANDLED_EXCEPTION,
    )


def instruction_line_number(instr: dis.Instruction | None) -> int | None:
    """Return the source line owned by *instr* when CPython exposes it."""
    if instr is None:
        return None
    if (line_number := get_position_line(instr)) is not None:
        return line_number
    return get_starts_line(instr)


def instruction_column(instr: dis.Instruction | None) -> int | None:
    """Return the source column owned by *instr* when CPython exposes it."""
    return None if instr is None else get_position_column(instr)


def state_pc(state: VMState | None, default: int = 0) -> int:
    """Return the current symbolic VM pc for exception source metadata."""
    value = getattr(state, "pc", default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def concrete_exception(
    exc_type: type[BaseException],
    *args: object,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
    line_number: int | None = None,
    column: int | None = None,
) -> SymbolicException:
    """Create an unconditional CPython runtime exception payload."""
    return SymbolicException.concrete(
        exc_type,
        *args,
        raised_at=state_pc(state) if raised_at is None else raised_at,
        line_number=instruction_line_number(instr) if line_number is None else line_number,
        column=instruction_column(instr) if column is None else column,
    )


def from_native_exception(
    exc: BaseException,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
) -> SymbolicException:
    """Create a modeled exception from a concrete Python exception instance."""
    return concrete_exception(
        type(exc),
        str(exc),
        state=state,
        instr=instr,
        raised_at=raised_at,
    )


def runtime_exception(
    exc_type: ExceptionType,
    *args: object,
    message: str | None = None,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
    condition: z3.BoolRef | None = None,
    line_number: int | None = None,
    column: int | None = None,
) -> SymbolicException:
    """Create a CPython exception payload, conditional when needed.

    Known builtin exception names are canonicalized to concrete exception
    classes. Unknown string names are preserved for user-defined modeled
    exceptions.
    """
    canonical = canonical_exception_type(exc_type)
    pc = state_pc(state) if raised_at is None else raised_at
    src_line = instruction_line_number(instr) if line_number is None else line_number
    src_col = instruction_column(instr) if column is None else column
    if condition is None or z3.is_true(condition):
        if isinstance(canonical, type):
            return SymbolicException.concrete(
                canonical,
                *args,
                raised_at=pc,
                line_number=src_line,
                column=src_col,
            )
        return SymbolicException(
            exc_type=canonical,
            args=tuple(args),
            message=message if message is not None else (str(args[0]) if args else None),
            raised_at=pc,
            condition=Z3_TRUE,
            category=ExceptionCategory.CUSTOM,
            line_number=src_line,
            column=src_col,
        )
    if isinstance(canonical, type):
        category = get_exception_category(canonical)
        resolved_message = message if message is not None else (str(args[0]) if args else None)
    else:
        category = ExceptionCategory.CUSTOM
        resolved_message = message if message is not None else (str(args[0]) if args else None)
    return SymbolicException(
        exc_type=canonical,
        args=tuple(args),
        message=resolved_message,
        raised_at=pc,
        condition=condition,
        category=category,
        line_number=src_line,
        column=src_col,
    )


def symbolic_exception(
    name: str,
    exc_type: ExceptionType,
    condition: z3.BoolRef,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
    message: str | None = None,
    args: tuple[object, ...] = (),
) -> SymbolicException:
    """Create a named conditional exception payload."""
    del name  # The carrier does not retain the display name today.
    return runtime_exception(
        exc_type,
        *args,
        message=message,
        state=state,
        instr=instr,
        raised_at=raised_at,
        condition=condition,
    )


def modeled_exception(
    exc_type: ExceptionType,
    *args: object,
    message: str | None = None,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
    condition: z3.BoolRef | None = None,
    confidence: float = 1.0,
    likelihood: float = 1.0,
) -> ModeledRuntimeException:
    """Create a routed runtime exception payload with confidence metadata."""
    canonical = canonical_exception_type(exc_type)
    pc = state_pc(state) if raised_at is None else raised_at
    src_line = instruction_line_number(instr)
    src_col = instruction_column(instr)
    resolved_message = message if message is not None else (str(args[0]) if args else None)
    if isinstance(canonical, type):
        category = get_exception_category(canonical)
    else:
        category = ExceptionCategory.CUSTOM
    return ModeledRuntimeException(
        exc_type=canonical,
        args=tuple(args),
        message=resolved_message,
        raised_at=pc,
        condition=Z3_TRUE if condition is None else condition,
        category=category,
        line_number=src_line,
        column=src_col,
        confidence=confidence,
        likelihood=likelihood,
    )


def type_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``TypeError`` payload."""
    return concrete_exception(TypeError, message, state=state, instr=instr)


def value_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``ValueError`` payload."""
    return concrete_exception(ValueError, message, state=state, instr=instr)


def index_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``IndexError`` payload."""
    return concrete_exception(IndexError, message, state=state, instr=instr)


def key_error(
    key: object,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``KeyError`` payload."""
    return concrete_exception(KeyError, key, state=state, instr=instr)


def attribute_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``AttributeError`` payload."""
    return concrete_exception(AttributeError, message, state=state, instr=instr)


def name_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``NameError`` payload."""
    return concrete_exception(NameError, message, state=state, instr=instr)


def unbound_local_error(
    message: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``UnboundLocalError`` payload."""
    return concrete_exception(UnboundLocalError, message, state=state, instr=instr)


def zero_division_error(
    message: str = "division by zero",
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a modeled ``ZeroDivisionError`` payload."""
    return concrete_exception(ZeroDivisionError, message, state=state, instr=instr)


def stop_iteration(
    value: object | None = None,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
) -> SymbolicException:
    """Create a modeled ``StopIteration`` payload."""
    if value is None:
        return concrete_exception(StopIteration, state=state, instr=instr, raised_at=raised_at)
    return concrete_exception(StopIteration, value, state=state, instr=instr, raised_at=raised_at)


def generator_exit(
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
    raised_at: int | None = None,
) -> SymbolicException:
    """Create a modeled ``GeneratorExit`` payload."""
    return concrete_exception(GeneratorExit, state=state, instr=instr, raised_at=raised_at)


def wrong_arity(
    function: str,
    expected: str,
    got: int,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a CPython-style argument-count ``TypeError`` payload."""
    return type_error(f"{function} expected {expected}, got {got}", state=state, instr=instr)


def wrong_type(
    function: str,
    value: object,
    expected: str,
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a CPython-style bad-type ``TypeError`` payload."""
    return type_error(
        f"{function} expected {expected}, got {type(value).__name__}",
        state=state,
        instr=instr,
    )


def domain_error(
    function: str,
    message: str = "math domain error",
    *,
    state: VMState | None = None,
    instr: dis.Instruction | None = None,
) -> SymbolicException:
    """Create a CPython-style numeric-domain ``ValueError`` payload."""
    del function
    return value_error(message, state=state, instr=instr)
