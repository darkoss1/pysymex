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

"""Operation mixin composition for the unified symbolic scalar carrier."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.value.additive import (
    ValueAdditiveMixin,
    bind_additive_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.bitwise.logic import (
    ValueBitwiseLogicMixin,
    bind_bitwise_logic_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.bitwise.xor import (
    ValueBitwiseXorMixin,
    bind_bitwise_xor_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.constants import (
    ValueConstantMixin,
    bind_constant_symbolic_value_classes,
)
from pysymex._internal.core.types.scalars.value.creators import (
    SymbolicValueCreatorMixin,
    bind_creator_symbolic_value_classes,
)
from pysymex._internal.core.types.scalars.value.division import (
    ValueDivisionMixin,
    bind_division_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.power import (
    ValuePowerMixin,
    bind_power_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.remainder import (
    ValueRemainderMixin,
    bind_remainder_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.shifts import (
    ValueShiftMixin,
    bind_shift_symbolic_value_class,
)
from pysymex._internal.core.types.scalars.value.specialization import (
    ValueSpecializationMixin,
    bind_symbolic_value_specializations,
)

if TYPE_CHECKING:
    from pysymex._internal.core.types.scalars.value.protocols import ValueConstructor


def bind_symbolic_value_arithmetic_classes(value_cls: ValueConstructor) -> None:
    """Bind the carrier class into all arithmetic mixin modules."""
    bind_additive_symbolic_value_class(value_cls)
    bind_remainder_symbolic_value_class(value_cls)
    bind_division_symbolic_value_class(value_cls)


def bind_symbolic_value_bitwise_classes(value_cls: ValueConstructor) -> None:
    """Bind the carrier class into all bitwise mixin modules."""
    bind_bitwise_logic_symbolic_value_class(value_cls)
    bind_bitwise_xor_symbolic_value_class(value_cls)
    bind_shift_symbolic_value_class(value_cls)
    bind_power_symbolic_value_class(value_cls)


def bind_symbolic_value_factory_classes(
    value_cls: ValueConstructor,
    string_cls: type[object],
) -> None:
    """Bind value and string classes into all factory mixin modules."""
    bind_creator_symbolic_value_classes(value_cls, string_cls)
    bind_symbolic_value_specializations(value_cls, string_cls)
    bind_constant_symbolic_value_classes(value_cls, string_cls)


class ValueArithmeticMixin(
    ValueDivisionMixin,
    ValueRemainderMixin,
    ValueAdditiveMixin,
):
    """Compose arithmetic operation implementations for ``SymbolicValue``."""


class SymbolicValueBitwiseMixin(
    ValuePowerMixin,
    ValueShiftMixin,
    ValueBitwiseXorMixin,
    ValueBitwiseLogicMixin,
):
    """Compose bitwise, shift, and power operations for ``SymbolicValue``."""


class SymbolicValueFactoryMixin(
    ValueConstantMixin,
    ValueSpecializationMixin,
    SymbolicValueCreatorMixin,
):
    """Compose construction and specialization helpers for ``SymbolicValue``."""
