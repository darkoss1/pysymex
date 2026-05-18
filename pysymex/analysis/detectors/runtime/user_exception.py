"""Detector for user-raised exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.detectors.base import Detector, IsSatFn, Issue, IssueKind
from pysymex.core.types.scalars import SymbolicValue

if TYPE_CHECKING:
    import dis

    from pysymex.core.state import VMState


class UserExceptionDetector(Detector):
    """Detects explicit exceptions raised via the RAISE_VARARGS opcode."""

    name = "user_exception"
    issue_kind = IssueKind.UNHANDLED_EXCEPTION

    def check(self, state: VMState, instruction: dis.Instruction, solver: IsSatFn) -> Issue | None:
        """Check for user-raised exceptions."""
        if instruction.opname != "RAISE_VARARGS":
            return None

        argc = instruction.arg if isinstance(instruction.arg, int) else 0
        if argc == 0:
            return None  # Re-raise

        if len(state.stack) < argc:
            return None

        # The exception object is at the top of the stack if argc == 1,
        # or just below the cause if argc == 2.
        exc_obj = state.stack[-argc]
        exc_obj_as_object: object = exc_obj

        exc_name = None
        if isinstance(exc_obj, type) and issubclass(exc_obj, BaseException):
            exc_name = exc_obj.__name__
        elif isinstance(exc_obj, BaseException):
            exc_name = type(exc_obj).__name__
        elif isinstance(exc_obj, SymbolicValue):
            symbolic_name = _normalize_symbolic_exception_name(exc_obj.name)
            if "Error" in symbolic_name or "Exception" in symbolic_name:
                exc_name = symbolic_name
        else:
            maybe_name = _extract_named_exception(exc_obj_as_object)
            if maybe_name is not None:
                exc_name = maybe_name

        if not exc_name:
            return None

        if exc_name == "AssertionError":
            return None

        if not solver(list(state.path_constraints)):
            return None

        return Issue(
            kind=self.issue_kind,
            message=f"Path raises unhandled exception: {exc_name}",
            pc=instruction.offset,
        )


def _extract_named_exception(value: object) -> str | None:
    """Return a string exception-like name from generic objects when available."""
    if not hasattr(value, "__dict__"):
        return None
    maybe_name = value.__dict__.get("name")
    if isinstance(maybe_name, str) and ("Error" in maybe_name or "Exception" in maybe_name):
        return _normalize_symbolic_exception_name(maybe_name)
    return None


def _normalize_symbolic_exception_name(name: str) -> str:
    """Return the builtin exception type from modeled instance names when possible."""
    marker = "_instance_"
    if marker in name:
        return name.split(marker, 1)[0]
    return name
