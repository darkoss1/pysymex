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

"""Attribute and generic argument write side-effect application."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.model.side.effects.writes import (
    has_precise_write_side_effect,
    record_generic_mutates_arg_write,
    record_modeled_attribute_write,
)
from pysymex._internal.execution.calls.object.maps import as_mapping

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def apply_attribute_mutation_effect(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Record attribute write facts from a model side-effect payload."""
    if "attribute_mutation" not in side_effects:
        return state
    mut = as_mapping(side_effects["attribute_mutation"])
    if mut is None:
        mut = {}
    return record_modeled_attribute_write(state, args, mut)


def apply_generic_mutates_arg_effect(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
) -> VMState:
    """Record a conservative write when a model only declares ``mutates_arg``."""
    if "mutates_arg" in side_effects and not has_precise_write_side_effect(side_effects):
        return record_generic_mutates_arg_write(state, args, side_effects["mutates_arg"])
    return state
