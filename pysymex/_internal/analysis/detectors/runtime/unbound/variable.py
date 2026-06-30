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

"""Unbound Variable detection module.

Detects potential `NameError` or `UnboundLocalError` exceptions by checking for access
to variables that are uninitialized or unbound.

Bug Class Detected:
    Unbound Variable Access.

Required Evidence:
    LOAD_FAST, LOAD_FAST_CHECK, LOAD_NAME, or LOAD_GLOBAL on a variable marked as
    UNBOUND or not present in globals/locals.

Issue Kinds:
    IssueKind.UNBOUND_VARIABLE
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.bytecode import global_name_from_argval
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.types import UNBOUND

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState


_BUILTIN_NAMES = frozenset(
    (
        "True",
        "False",
        "None",
        "all",
        "any",
        "print",
        "len",
        "range",
        "str",
        "int",
        "float",
        "list",
        "dict",
        "set",
        "tuple",
        "bool",
        "type",
        "isinstance",
        "hasattr",
        "getattr",
        "setattr",
        "callable",
        "iter",
        "next",
        "zip",
        "map",
        "filter",
        "sum",
        "min",
        "max",
        "abs",
        "round",
        "sorted",
        "reversed",
        "enumerate",
        "open",
        "input",
        "BaseException",
        "Exception",
        "ArithmeticError",
        "ValueError",
        "TypeError",
        "KeyError",
        "IndexError",
        "LookupError",
        "AttributeError",
        "RuntimeError",
        "ZeroDivisionError",
        "OverflowError",
        "OSError",
        "ImportError",
        "NameError",
        "UnboundLocalError",
        "StopIteration",
        "StopAsyncIteration",
        "id",
        "slice",
        "property",
        "classmethod",
        "staticmethod",
        "super",
        "vars",
        "dir",
        "help",
        "repr",
        "ascii",
        "intern",
    ),
)
_INTERNAL_PREFIXES = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")


class UnboundVariableDetector(Detector):
    """Detect use of unbound or uninitialized local and global variables.

    Bug class:
        ``NameError`` (``LOAD_NAME`` / ``LOAD_GLOBAL`` on a missing name) or
        ``UnboundLocalError`` (``LOAD_FAST`` / ``LOAD_FAST_CHECK`` on
        a local marked ``UNBOUND``).

    Evidence:
        Variable slot is ``UNBOUND`` in the VM state, or the name is
        absent from both ``local_vars`` and ``global_vars``.

    Issue kind:
        ``IssueKind.UNBOUND_VARIABLE``.

    Known false-positive conditions:
        Builtin names in ``BUILTIN_NAMES`` are excluded.  Short
        upper-case names (single-letter type variables) are also
        skipped.  Names matching ``INTERNAL_PREFIXES`` are excluded.
    """

    name = "unbound-variable"
    description = "Detects potential NameError from unbound variables"
    issue_kind = IssueKind.UNBOUND_VARIABLE
    relevant_opcodes = frozenset(("LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_NAME", "LOAD_GLOBAL"))

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for a load of an unbound variable on a feasible path."""
        return _check_unbound_variable(state, instruction, _solver_check, self.relevant_opcodes)


def _check_unbound_variable(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
    relevant_opcodes: frozenset[str],
) -> Issue | None:
    """Inspect a load instruction for an unbound variable on a feasible path."""
    if instruction.opname not in relevant_opcodes:
        return None
    if not isinstance(instruction.argval, str):
        return None

    var_name = _load_variable_name(instruction)
    if _should_skip_name(var_name, instruction.opname):
        return None
    if not _name_is_unbound(state, instruction.opname, var_name):
        return None

    constraints = list(state.path_constraints)
    model = get_model_if_satisfiable_result(constraints, solver_check).model
    if model is None:
        return None

    return Issue(
        kind=_issue_kind_for_unbound_load(instruction.opname),
        message=f"Variable '{var_name}' may be unbound ({_error_name(instruction.opname)})",
        constraints=constraints,
        model=model,
        pc=state.pc,
    )


def _load_variable_name(instruction: dis.Instruction) -> str:
    """Return the user-visible variable name loaded by *instruction*."""
    if instruction.opname == "LOAD_GLOBAL":
        return global_name_from_argval(instruction.argval)
    return instruction.argval


def _should_skip_name(var_name: str, instruction_name: str) -> bool:
    """Return True for names intentionally excluded from unbound checks."""
    if instruction_name in {"LOAD_NAME", "LOAD_GLOBAL"} and var_name in _BUILTIN_NAMES:
        return True
    if any(var_name.startswith(prefix) for prefix in _INTERNAL_PREFIXES):
        return True
    return bool(len(var_name) <= 2 and var_name[0].isupper())


def _name_is_unbound(state: VMState, instruction_name: str, var_name: str) -> bool:
    """Return whether *var_name* is unbound for the load opcode semantics."""
    if instruction_name == "LOAD_FAST_CHECK" and var_name not in state.local_vars:
        return True
    if instruction_name in {"LOAD_FAST", "LOAD_FAST_CHECK"}:
        return state.get_local(var_name) is UNBOUND
    if instruction_name == "LOAD_NAME":
        return var_name not in state.local_vars and var_name not in state.global_vars
    if instruction_name == "LOAD_GLOBAL":
        return var_name not in state.global_vars
    return False


def _issue_kind_for_unbound_load(instruction_name: str) -> IssueKind:
    """Return the report kind for the unbound load opcode."""
    if instruction_name == "LOAD_GLOBAL":
        return IssueKind.NAME_ERROR
    return IssueKind.UNBOUND_VARIABLE


def _error_name(instruction_name: str) -> str:
    """Return the CPython error family for the unbound load opcode."""
    if instruction_name in {"LOAD_NAME", "LOAD_GLOBAL"}:
        return "NameError"
    return "UnboundLocalError"
