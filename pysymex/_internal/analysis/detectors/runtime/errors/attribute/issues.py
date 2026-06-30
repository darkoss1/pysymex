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

"""Issue construction for the ``AttributeError`` detector."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.outcome import IssueKind

from .evidence import (
    collect_invalid_attr_conditions,
    has_attribute_in_concrete_types,
)
from .modeling import (
    has_dynamic_attribute_hook,
    modeled_object_can_delete_attr,
    modeled_object_can_store_attr,
    modeled_object_has_attribute,
    modeled_object_has_readonly_prop,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.scalars.values import SymbolicValue

INTERNAL_SYMBOLIC_ATTR_PREFIXES = ("self.", "cls.")


def symbolic_value_attribute_issue(
    obj: SymbolicValue,
    attr_name: str,
    opname: str,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build missing-attribute evidence for symbolic scalar/model-backed values."""
    if obj.name.startswith(INTERNAL_SYMBOLIC_ATTR_PREFIXES):
        return None

    modeled_object = getattr(obj, "_modeled_object", None)
    if opname == "STORE_ATTR":
        if modeled_object_can_store_attr(modeled_object, attr_name):
            return None
        store_issue = modeled_store_attribute_issue(
            obj,
            modeled_object,
            attr_name,
            state,
            solver_check,
        )
        if store_issue is not None:
            return store_issue
    if opname == "DELETE_ATTR" and modeled_object_can_delete_attr(modeled_object):
        return None

    modeled_has_attr = modeled_object_has_attribute(modeled_object, attr_name)
    if modeled_has_attr is True:
        return None
    if modeled_has_attr is False and not has_dynamic_attribute_hook(modeled_object):
        return attribute_issue(
            message=f"Possible AttributeError: '{obj.name}' may not have attribute '{attr_name}'",
            constraints=list(state.path_constraints),
            state=state,
            solver_check=solver_check,
        )

    invalid_conditions = collect_invalid_attr_conditions(obj, attr_name)
    if not invalid_conditions:
        return None
    return attribute_issue(
        message=f"Possible AttributeError: '{obj.name}' may not have attribute '{attr_name}'",
        constraints=[*state.path_constraints, z3.Or(*invalid_conditions)],
        state=state,
        solver_check=solver_check,
    )


def modeled_store_attribute_issue(
    obj: SymbolicValue,
    modeled_object: object,
    attr_name: str,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build read-only modeled property evidence for ``STORE_ATTR``, if any."""
    if not modeled_object_has_readonly_prop(modeled_object, attr_name):
        return None
    return attribute_issue(
        message=(
            f"Possible AttributeError: '{obj.name}' may not have writable attribute '{attr_name}'"
        ),
        constraints=list(state.path_constraints),
        state=state,
        solver_check=solver_check,
    )


def concrete_attribute_issue(
    obj: object,
    attr_name: str,
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Build missing-attribute evidence for concrete receiver objects."""
    if has_attribute_in_concrete_types(obj, attr_name):
        return None
    return attribute_issue(
        message=f"Possible AttributeError: '{type(obj).__name__}' has no attribute '{attr_name}'",
        constraints=list(state.path_constraints),
        state=state,
        solver_check=solver_check,
    )


def attribute_issue(
    *,
    message: str,
    constraints: list[z3.BoolRef],
    state: VMState,
    solver_check: IsSatFn,
) -> Issue | None:
    """Return an ``AttributeError`` issue only when the evidence path is satisfiable."""
    model = get_model_if_satisfiable_result(constraints, solver_check).model
    if model is None:
        return None
    return Issue(
        kind=IssueKind.ATTRIBUTE_ERROR,
        message=message,
        constraints=constraints,
        model=model,
        pc=state.pc,
    )
