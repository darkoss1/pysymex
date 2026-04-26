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

from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class UnboundVariableDetector(Detector):
    """Detects potential use of unbound/uninitialized variables.
    Checks for LOAD_NAME/LOAD_FAST operations on variables that may not
    have been assigned on all code paths.
    """

    name = "unbound-variable"
    description = "Detects potential NameError from unbound variables"
    issue_kind = IssueKind.UNBOUND_VARIABLE
    relevant_opcodes = frozenset({"LOAD_FAST", "LOAD_FAST_CHECK"})
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

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check."""
        if instruction.opname in ("LOAD_FAST", "LOAD_FAST_CHECK"):
            var_name = instruction.argval

            if var_name in self.BUILTIN_NAMES:
                return None

            if any(var_name.startswith(p) for p in self.INTERNAL_PREFIXES):
                return None

            if len(var_name) <= 2 and var_name[0].isupper():
                return None
            from pysymex.core.state import UNBOUND

            if state.get_local(var_name) is UNBOUND:
                return Issue(
                    kind=IssueKind.UNBOUND_VARIABLE,
                    message=f"Variable '{var_name}' may be unbound (NameError)",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                )
        return None
