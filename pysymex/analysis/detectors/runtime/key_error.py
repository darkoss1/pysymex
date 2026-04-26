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
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.scalars import (
    SymbolicDict,
    SymbolicString,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn


class KeyErrorDetector(Detector):
    """Detects subscript access on a ``SymbolicDict`` with a possibly-missing key."""

    name = "key-error"
    description = "Detects missing dictionary keys"
    issue_kind = IssueKind.KEY_ERROR
    relevant_opcodes = frozenset({"BINARY_SUBSCR"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check for missing-key access on symbolic dicts."""
        if instruction.opname != "BINARY_SUBSCR":
            return None
        if len(state.stack) < 2:
            return None
        key = state.stack[-1]
        container = state.stack[-2]

        if is_type_subscription(container):
            return None
        if not isinstance(container, SymbolicDict):
            return None

        normalized_key: SymbolicString | None = None
        if isinstance(key, SymbolicString):
            normalized_key = key
        elif isinstance(key, str):
            normalized_key = SymbolicString.from_const(key)

        if normalized_key is None:
            return None

        missing_key: list[z3.BoolRef] = [
            *state.path_constraints,
            z3.Not(container.contains_key(normalized_key).z3_bool),
        ]
        if is_satisfiable(missing_key):
            return Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError: {container.name} may not contain key",
                constraints=missing_key,
                model=get_model(missing_key),
                pc=state.pc,
            )
        return None
