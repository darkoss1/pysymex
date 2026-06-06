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

"""complex instance method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.numeric.shared import numeric_type_error_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class ComplexConjugateModel(FunctionModel):
    """Model for complex.conjugate() - returns a complex with a negated imaginary part."""

    name = "conjugate"
    qualname = "complex.conjugate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return numeric_type_error_result(self.qualname, state)
        result, constraint = SymbolicValue.symbolic(f"complex_conjugate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


__all__ = ["ComplexConjugateModel"]
