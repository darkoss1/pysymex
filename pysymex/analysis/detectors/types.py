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

"""Detection context for bytecode-level detector helpers.

``DetectionContext`` bundles analysis data available at a given bytecode
offset for pattern-aware checks shared across detector families.
"""

from __future__ import annotations

import dis
import types
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex.typing import to_string_set
from pysymex.analysis.detectors.detector.types import IssueKind
from pysymex.analysis.static.flow.context import FlowContext
from pysymex.analysis.static.patterns import (
    FunctionPatternInfo,
    PatternMatch,
    PatternKind,
)
from pysymex.analysis.static.types import (
    PyType,
    TypeEnvironment,
    TypeKind,
)

if TYPE_CHECKING:
    from pysymex.analysis.static.control.models import ControlFlowGraph
    from pysymex.core.state.record import VMState


@dataclass
class DetectionContext:
    """Snapshot of analysis state at a single bytecode offset.

    Bundles the code object, instruction sequence, inferred types,
    flow context, pattern matches, optional CFG, and optional symbolic
    state so that detectors can query any combination.
    """

    code: types.CodeType
    instructions: Sequence[dis.Instruction]
    pc: int
    instruction: dis.Instruction
    line: int
    type_env: TypeEnvironment
    flow_context: FlowContext | None = None
    pattern_info: FunctionPatternInfo | None = None
    file_path: str = ""
    function_name: str = ""
    symbolic_state: VMState | None = None
    patterns: Sequence[PatternMatch] | FunctionPatternInfo | None = None
    cfg: ControlFlowGraph | None = None
    imports: set[str] | None = None
    global_types: Mapping[str, PyType] | None = None

    def get_type(self, var_name: str) -> PyType:
        """Return the inferred type of *var_name* from the type environment."""
        return self.type_env.get_type(var_name)

    def is_definitely_type(self, var_name: str, kind: TypeKind) -> bool:
        """Return ``True`` if *var_name* is inferred to be exactly *kind*."""
        var_type = self.type_env.get_type(var_name)
        return var_type.kind == kind

    def can_pattern_suppress(self, error_type: str) -> bool:
        """Return ``True`` if a matched pattern already guards against *error_type*."""
        if self.pattern_info is None:
            return False
        return not self.pattern_info.can_error_occur(self.pc, error_type)

    def is_in_try_block(self, exception_type: str) -> bool:
        """Return ``True`` if the current offset is inside a try/except catching *exception_type*."""
        if self.pattern_info is None:
            return False
        patterns = self.pattern_info.get_patterns_at(self.pc)
        for pattern in patterns:
            if pattern.kind == PatternKind.TRY_EXCEPT_PATTERN:
                raw_caught = pattern.variables.get("caught_exceptions", set[str]())
                caught = to_string_set(raw_caught)
                if exception_type in caught or "Exception" in caught:
                    return True
        return False


__all__ = ["DetectionContext", "IssueKind"]
