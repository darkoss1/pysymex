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

"""Public model side-effect application orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.calls.model.side.effects.attributes import (
    apply_attribute_mutation_effect,
    apply_generic_mutates_arg_effect,
)
from pysymex._internal.execution.calls.model.side.effects.containers import (
    apply_dict_mutation_effect,
    apply_list_mutation_effect,
    apply_simple_item_mutation_effects,
)
from pysymex._internal.execution.calls.model.side.effects.iterators import (
    apply_iterator_mutation_effect,
    apply_iterator_source_mutation_effects,
)
from pysymex._internal.execution.calls.model.side.effects.types import (
    PathFeasibilityPredicate,
    SideEffectApplication,
)
from pysymex._internal.execution.model.effects.core import issues_from_model_side_effects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def apply_model_side_effects(
    state: VMState,
    args: list[StackValue],
    side_effects: dict[str, object],
    reportable_path_is_sat: PathFeasibilityPredicate,
) -> SideEffectApplication:
    """Apply model side effects to state and return generated detector issues."""
    generated_issues = issues_from_model_side_effects(
        side_effects,
        state.pc,
        path_constraints=list(state.path_constraints),
        path_may_be_feasible=reportable_path_is_sat,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )

    state = apply_list_mutation_effect(state, args, side_effects)
    state = apply_dict_mutation_effect(state, args, side_effects)
    state = apply_simple_item_mutation_effects(state, args, side_effects)
    state = apply_attribute_mutation_effect(state, args, side_effects)
    state = apply_generic_mutates_arg_effect(state, args, side_effects)
    state = apply_iterator_mutation_effect(state, args, side_effects)
    state = apply_iterator_source_mutation_effects(state, side_effects)
    return SideEffectApplication(state=state, issues=generated_issues)
