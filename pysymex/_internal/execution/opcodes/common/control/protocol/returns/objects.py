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

"""Modeled-object predicates shared by protocol return normalization."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


class ProtocolObjectPredicates:
    """Domain owner for modeled-object shape checks during protocol returns."""

    @staticmethod
    def is_modeled(value: StackValue) -> bool:
        """Return whether the value is definitely a modeled heap object."""
        return (
            isinstance(value, SymbolicValue)
            and getattr(value, "_modeled_object", None) is not None
            and z3.is_true(simplify_expr(value.is_obj))
        )

    @staticmethod
    def is_non_object(value: StackValue) -> bool:
        """Return whether the value is definitely not a heap object."""
        if isinstance(value, SymbolicNoneType):
            return True
        if isinstance(value, SymbolicValue):
            return z3.is_false(simplify_expr(value.is_obj))
        return value is None or isinstance(value, (bool, int, float, str, bytes))

    @staticmethod
    def instance_id(value: StackValue) -> int | None:
        """Return the modeled instance id when the value is a definite instance."""
        if not ProtocolObjectPredicates.is_modeled(value):
            return None
        from pysymex._internal.core.classes.instances import SymbolicInstance

        modeled_object = getattr(value, "_modeled_object", None)
        if not isinstance(modeled_object, SymbolicInstance):
            return None
        return modeled_object.instance_id
