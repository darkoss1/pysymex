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

"""Detect ``AttributeError`` from attribute loads, stores, and deletes on known objects.

Bug class:
    ``AttributeError`` - an attribute access on a primitive, symbolic, or
    modeled object that is provably absent or read-only.

Evidence:
    Satisfiable path constraints where the object's type does not expose
    the requested attribute.

Issue kind:
    ``IssueKind.ATTRIBUTE_ERROR``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue

from .evidence import attribute_access_is_supported, resolve_attr_name
from .issues import concrete_attribute_issue, symbolic_value_attribute_issue

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState


class AttributeErrorDetector(Detector):
    """Detect ``AttributeError`` exceptions on attribute loads, stores, and deletes.

    Bug class:
        ``AttributeError`` - an attribute lookup or write that is provably
        absent or read-only for the object's known type.

    Evidence:
        Satisfiable path constraints under which the object lacks the
        requested attribute, or has a read-only property being written.

    Issue kind:
        ``IssueKind.ATTRIBUTE_ERROR``.

    Known false-positive conditions:
        - Havoc-widened objects are skipped (returns ``None``).
        - Modeled objects with dynamic hooks (``__getattr__``/``__getattribute__``)
          or mutation hooks such as ``__delattr__`` are skipped where the hook
          owns the operation.
        - Symbolic objects (``SymbolicObject``) are skipped as their attribute
          model is maintained separately.
    """

    name = "attribute-error"
    description = "Detects missing attributes"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset(("LOAD_ATTR", "STORE_ATTR", "DELETE_ATTR", "LOAD_SUPER_ATTR"))

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Inspect *instruction* for an attribute access that may raise ``AttributeError``.

        Checks ``LOAD_ATTR``, ``STORE_ATTR``, ``DELETE_ATTR``, and
        ``LOAD_SUPER_ATTR`` against the object at TOS, returning an issue
        when the attribute is provably absent or read-only and the path is
        feasible.
        """
        return _check_attribute_error(self, state, instruction, _solver_check)


def _check_attribute_error(
    detector: AttributeErrorDetector,
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Inspect one attribute opcode for missing or read-only attribute evidence."""
    target = _attribute_access_target(detector, state, instruction)
    if target is None:
        return None
    attr_name, obj = target

    if attribute_access_is_supported(obj, attr_name, state):
        return None
    if isinstance(obj, SymbolicObject):
        return None
    if isinstance(obj, SymbolicValue):
        return symbolic_value_attribute_issue(
            obj,
            attr_name,
            instruction.opname,
            state,
            solver_check,
        )
    return concrete_attribute_issue(obj, attr_name, state, solver_check)


def _attribute_access_target(
    detector: AttributeErrorDetector,
    state: VMState,
    instruction: dis.Instruction,
) -> tuple[str, object] | None:
    """Resolve the attribute name and receiver object for an attribute opcode."""
    if instruction.opname not in detector.relevant_opcodes:
        return None
    if not state.stack:
        return None

    attr_name = resolve_attr_name(instruction.argval)
    if not attr_name:
        return None
    return attr_name, state.stack[-1]
