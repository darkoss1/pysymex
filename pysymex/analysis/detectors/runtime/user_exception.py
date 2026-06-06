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

"""Detect user-raised exceptions (explicit ``raise``) reachable on feasible paths.

Bug class:
    ``RAISE_VARARGS`` or ``RERAISE`` on a satisfiable path, indicating
    an unhandled exception that always propagates to the caller.

Evidence:
    Path constraints at the ``raise`` site are satisfiable.

Issue kind:
    ``IssueKind.UNHANDLED_EXCEPTION``.

Known false-positive conditions:
    ``AssertionError`` (raised by ``assert``) is excluded because it is
    covered by a dedicated assertion detector.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.logger import get_logger

if TYPE_CHECKING:
    import dis

    from pysymex.core.state.record import VMState

logger = get_logger(__name__)
_SOLVER_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)
_MODELED_RUNTIME_ISSUE_KINDS: dict[str, IssueKind] = {
    "ValueError": IssueKind.VALUE_ERROR,
}


class UserExceptionDetector(Detector):
    """Detect explicitly raised exceptions via ``RAISE_VARARGS`` / ``RERAISE``."""

    name = "user_exception"
    issue_kind = IssueKind.UNHANDLED_EXCEPTION
    relevant_opcodes = frozenset({"RAISE_VARARGS", "RERAISE"})

    def check(self, state: VMState, instruction: dis.Instruction, solver: IsSatFn) -> Issue | None:
        """Inspect *instruction* for a ``raise`` on a feasible path.

        Extracts the exception object from the VM state (active exception,
        top-of-stack, or pending reraise), resolves its name, and returns
        an issue if the path constraints are satisfiable.
        """
        if instruction.opname == "RERAISE":
            exc_obj = state.pending_reraise_exception
            if exc_obj is None:
                return None
        elif instruction.opname != "RAISE_VARARGS":
            return None
        else:
            argc = instruction.arg if isinstance(instruction.arg, int) else 0
            if argc == 0:
                exc_obj = state.active_exception
                if exc_obj is None:
                    return None
            else:
                if len(state.stack) < argc:
                    return None
                # The exception object is at the top of the stack if argc == 1,
                # or just below the cause if argc == 2.
                exc_obj = state.stack[-argc]

        exc_name = _exception_name(exc_obj)

        if not exc_name:
            return None

        if exc_name == "AssertionError":
            return None

        if not _path_is_feasible(list(state.path_constraints), solver):
            return None

        issue_kind = _issue_kind_for_exception(exc_obj, exc_name)
        detail = _exception_detail(exc_obj)
        if issue_kind == IssueKind.UNHANDLED_EXCEPTION:
            message = f"Path raises unhandled exception: {exc_name}"
            if detail:
                message = f"{message}: {detail}"
        else:
            message = f"Possible {exc_name}"
            if detail:
                message = f"{message}: {detail}"

        return Issue(kind=issue_kind, message=message, pc=instruction.offset)


def _exception_name(value: object) -> str | None:
    """Return the reportable exception type represented by a VM value."""
    if isinstance(value, type):
        return value.__name__ if issubclass(value, BaseException) else None
    if isinstance(value, BaseException):
        return type(value).__name__
    if isinstance(value, SymbolicValue):
        symbolic_name = _normalize_symbolic_exception_name(value.name)
        return symbolic_name if "Error" in symbolic_name or "Exception" in symbolic_name else None
    return _extract_named_exception(value)


def _extract_named_exception(value: object) -> str | None:
    """Return a string exception-like name from generic objects when available."""
    type_name = getattr(value, "type_name", None)
    if isinstance(type_name, str) and ("Error" in type_name or "Exception" in type_name):
        return _normalize_symbolic_exception_name(type_name)
    if not hasattr(value, "__dict__"):
        return None
    maybe_name = value.__dict__.get("name")
    if isinstance(maybe_name, str) and ("Error" in maybe_name or "Exception" in maybe_name):
        return _normalize_symbolic_exception_name(maybe_name)
    return None


def _issue_kind_for_exception(value: object, exc_name: str) -> IssueKind:
    """Return a specific runtime issue kind for internally modeled exceptions."""
    if isinstance(value, SymbolicException):
        return _MODELED_RUNTIME_ISSUE_KINDS.get(exc_name, IssueKind.UNHANDLED_EXCEPTION)
    return IssueKind.UNHANDLED_EXCEPTION


def _exception_detail(value: object) -> str | None:
    """Return a stable exception detail for modeled runtime exceptions."""
    if isinstance(value, SymbolicException):
        return value.message
    return None


def _normalize_symbolic_exception_name(name: str) -> str:
    """Return the builtin exception type from modeled instance names when possible."""
    marker = "_instance_"
    if marker in name:
        return name.split(marker, 1)[0]
    return name


def _path_is_feasible(path_constraints: list[z3.BoolRef], solver: IsSatFn) -> bool:
    """Return path feasibility evidence, treating solver callback failures as inconclusive."""
    try:
        return solver(path_constraints)
    except _SOLVER_FAILURES:
        logger.debug("User-exception path feasibility check failed; treating as inconclusive")
        return False
