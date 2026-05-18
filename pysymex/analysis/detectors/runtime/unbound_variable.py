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

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.state import UNBOUND
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class UnboundVariableDetector(Detector):
    """Detects potential use of unbound/uninitialized variables.
    Checks for LOAD_NAME/LOAD_FAST operations on variables that may not
    have been assigned on all code paths.
    """

    name = "unbound-variable"
    description = "Detects potential NameError from unbound variables"
    issue_kind = IssueKind.UNBOUND_VARIABLE
    relevant_opcodes = frozenset({"LOAD_FAST", "LOAD_FAST_CHECK", "LOAD_NAME"})
    BUILTIN_NAMES = frozenset(
        {
            "True",
            "False",
            "None",
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
            "Exception",
            "ValueError",
            "TypeError",
            "KeyError",
            "IndexError",
            "AttributeError",
            "RuntimeError",
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

    def _should_skip_name(self, var_name: str) -> bool:
        """Return True for names intentionally excluded from unbound checks."""
        if var_name in self.BUILTIN_NAMES:
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
        """Check."""
        if instruction.opname not in self.relevant_opcodes:
            return None
        if not isinstance(instruction.argval, str):
            return None

        var_name = instruction.argval
        if self._should_skip_name(var_name):
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

        if not is_unbound:
            return None

        constraints = list(state.path_constraints)
        if not _solver_check(constraints):
            return None

        error_name = "NameError" if instruction.opname == "LOAD_NAME" else "UnboundLocalError"
        return Issue(
            kind=IssueKind.UNBOUND_VARIABLE,
            message=f"Variable '{var_name}' may be unbound ({error_name})",
            constraints=constraints,
            pc=state.pc,
        )
