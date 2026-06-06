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

import dis
from typing import TYPE_CHECKING

from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable
from pysymex.core.bytecode import global_name_from_argval
from pysymex.core.state.types import UNBOUND

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


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
    relevant_opcodes = frozenset({"LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_NAME", "LOAD_GLOBAL"})
    BUILTIN_NAMES = frozenset(
        {
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
        }
    )

    INTERNAL_PREFIXES = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")

    def _should_skip_name(self, var_name: str, instruction_name: str) -> bool:
        """Return True for names intentionally excluded from unbound checks."""
        if instruction_name in {"LOAD_NAME", "LOAD_GLOBAL"} and var_name in self.BUILTIN_NAMES:
            return True
        if any(var_name.startswith(prefix) for prefix in self.INTERNAL_PREFIXES):
            return True
        if len(var_name) <= 2 and var_name[0].isupper():
            return True
        return False

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for a load of an unbound variable on a feasible path."""
        if instruction.opname not in self.relevant_opcodes:
            return None
        if not isinstance(instruction.argval, str):
            return None

        var_name = (
            global_name_from_argval(instruction.argval)
            if instruction.opname == "LOAD_GLOBAL"
            else instruction.argval
        )
        if self._should_skip_name(var_name, instruction.opname):
            return None

        is_unbound = False
        if instruction.opname in {"LOAD_FAST", "LOAD_FAST_CHECK"}:
            is_unbound = state.get_local(var_name) is UNBOUND
        elif instruction.opname == "LOAD_NAME":
            if var_name in state.local_vars:
                is_unbound = False
            elif var_name in state.global_vars:
                is_unbound = False
            else:
                is_unbound = True
        elif instruction.opname == "LOAD_GLOBAL":
            is_unbound = var_name not in state.global_vars

        if not is_unbound:
            return None

        constraints = list(state.path_constraints)
        model = get_model_if_satisfiable(constraints, _solver_check)
        if model is None:
            return None

        error_name = (
            "NameError"
            if instruction.opname in {"LOAD_NAME", "LOAD_GLOBAL"}
            else "UnboundLocalError"
        )
        kind = (
            IssueKind.NAME_ERROR
            if instruction.opname == "LOAD_GLOBAL"
            else IssueKind.UNBOUND_VARIABLE
        )
        return Issue(
            kind=kind,
            message=f"Variable '{var_name}' may be unbound ({error_name})",
            constraints=constraints,
            model=model,
            pc=state.pc,
        )
