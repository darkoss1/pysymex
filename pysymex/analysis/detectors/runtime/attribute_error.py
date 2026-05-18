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
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex.core.state import VMState

import z3
from pysymex.core.objects.types import (
    SymbolicObject as OOPObject,
)
from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicObject
from pysymex.core.types import SymbolicString, SymbolicValue
from pysymex.core.types.havoc import is_havoc
from pysymex.core.solver.engine import get_model
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn

_BUILTIN_ATTRS_BY_KIND: dict[str, frozenset[str]] = {
    "int": frozenset(dir(int)),
    "float": frozenset(dir(float)),
    "bool": frozenset(dir(bool)),
    "str": frozenset(dir(str)),
    "list": frozenset(dir(list)),
    "dict": frozenset(dir(dict)),
    "tuple": frozenset(dir(tuple)),
    "set": frozenset(dir(set)),
    "bytes": frozenset(dir(bytes)),
}

_SYMBOLIC_TYPE_CONDITIONS: tuple[tuple[str, str], ...] = (
    ("int", "is_int"),
    ("float", "is_float"),
    ("bool", "is_bool"),
    ("str", "is_str"),
    ("list", "is_list"),
    ("dict", "is_dict"),
)
_INTERNAL_SYMBOLIC_ATTR_PREFIXES = ("self.", "cls.")


def _resolve_attr_name(raw_attr: object) -> str:
    """Convert bytecode argval to an attribute-name string."""
    if isinstance(raw_attr, str):
        return raw_attr
    if raw_attr is None:
        return ""
    return str(raw_attr)


def _is_known_symbolic_primitive(obj: SymbolicValue, kind: str, flag: str) -> bool:
    """Return True when SymbolicValue is known to include the given primitive kind."""
    if obj.affinity_type == kind:
        return True
    flag_value = getattr(obj, flag)
    return z3.is_true(flag_value)


def _collect_invalid_attr_conditions(
    obj: SymbolicValue,
    attr_name: str,
) -> list[z3.BoolRef]:
    """Collect satisfiable primitive-type conditions where *attr_name* is invalid."""
    invalid_conditions: list[z3.BoolRef] = []
    for type_name, flag_name in _SYMBOLIC_TYPE_CONDITIONS:
        if attr_name in _BUILTIN_ATTRS_BY_KIND[type_name]:
            continue
        if _is_known_symbolic_primitive(obj, type_name, flag_name):
            invalid_conditions.append(getattr(obj, flag_name))
    return invalid_conditions


def _has_attribute_in_concrete_types(obj: object, attr_name: str) -> bool:
    """Return whether any concrete runtime type of *obj* supports *attr_name*."""
    candidate_types: Sequence[type[object]] = (
        int,
        float,
        bool,
        str,
        list,
        dict,
        tuple,
        set,
        bytes,
    )
    for concrete_type in candidate_types:
        if isinstance(obj, concrete_type):
            return attr_name in _BUILTIN_ATTRS_BY_KIND[concrete_type.__name__]
    try:
        return hasattr(obj, attr_name)
    except Exception:
        return False


def _symbolic_container_kind(obj: object, state: VMState) -> str | None:
    """Resolve symbolic container wrappers to their Python container kind."""
    if isinstance(obj, SymbolicString):
        return "str"
    if isinstance(obj, SymbolicList):
        return "list"
    if isinstance(obj, SymbolicDict):
        return "dict"
    if isinstance(obj, SymbolicObject):
        obj_state = state.memory.get(obj.address)
        if isinstance(obj_state, SymbolicList):
            return "list"
        if isinstance(obj_state, SymbolicDict):
            return "dict"
    if isinstance(obj, SymbolicValue):
        if obj.affinity_type in _BUILTIN_ATTRS_BY_KIND:
            return obj.affinity_type
        if getattr(obj, "_type", None) in _BUILTIN_ATTRS_BY_KIND:
            return str(getattr(obj, "_type"))
    return None


def _has_dynamic_attribute_hook(obj: object) -> bool:
    enhanced_class = getattr(obj, "enhanced_class", None)
    if enhanced_class is None:
        return False
    get_method = getattr(enhanced_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


def _enhanced_object_has_attribute(obj: object, attr_name: str) -> bool | None:
    get_attribute = cast(
        "Callable[[str], tuple[object, bool]] | None",
        getattr(obj, "get_attribute", None),
    )
    if not callable(get_attribute):
        return None
    _value, found = get_attribute(attr_name)
    return bool(found)


def _enhanced_object_can_store_attribute(obj: object, attr_name: str) -> bool:
    enhanced_class = getattr(obj, "enhanced_class", None)
    if enhanced_class is None:
        return False
    get_method = getattr(enhanced_class, "get_method", None)
    if callable(get_method) and get_method("__setattr__") is not None:
        return True
    properties_obj = getattr(enhanced_class, "properties", {})
    if isinstance(properties_obj, dict) and attr_name in properties_obj:
        properties = cast("dict[str, object]", properties_obj)
        prop = properties[attr_name]
        return getattr(prop, "fset", None) is not None
    slots = getattr(enhanced_class, "slots", None)
    return slots is None or attr_name in slots


def _enhanced_object_has_readonly_property(obj: object, attr_name: str) -> bool:
    enhanced_class = getattr(obj, "enhanced_class", None)
    if enhanced_class is None:
        return False
    properties_obj = getattr(enhanced_class, "properties", {})
    if not isinstance(properties_obj, dict) or attr_name not in properties_obj:
        return False
    properties = cast("dict[str, object]", properties_obj)
    return getattr(properties[attr_name], "fset", None) is None


class AttributeErrorDetector(Detector):
    """Detects attribute access errors."""

    name = "attribute-error"
    description = "Detects missing attributes"
    issue_kind = IssueKind.ATTRIBUTE_ERROR
    relevant_opcodes = frozenset({"LOAD_ATTR", "STORE_ATTR", "DELETE_ATTR", "LOAD_SUPER_ATTR"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check whether the attribute access can fail on known primitive targets."""
        if instruction.opname not in self.relevant_opcodes:
            return None
        if not state.stack:
            return None

        attr_name = _resolve_attr_name(instruction.argval)
        if not attr_name:
            return None

        obj = state.stack[-1]
        if is_havoc(obj):
            return None
        container_kind = _symbolic_container_kind(obj, state)
        if container_kind is not None and attr_name in _BUILTIN_ATTRS_BY_KIND[container_kind]:
            return None

        if isinstance(obj, (SymbolicObject, OOPObject)):
            return None

        if isinstance(obj, SymbolicValue):
            if obj.name.startswith(_INTERNAL_SYMBOLIC_ATTR_PREFIXES):
                return None
            enhanced_obj = getattr(obj, "_enhanced_object", None)
            if instruction.opname == "STORE_ATTR":
                if _enhanced_object_can_store_attribute(enhanced_obj, attr_name):
                    return None
                if _enhanced_object_has_readonly_property(enhanced_obj, attr_name):
                    constraints = list(state.path_constraints)
                    if not _solver_check(constraints):
                        return None
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message=(
                            f"Possible AttributeError: '{obj.name}' may not have writable "
                            f"attribute '{attr_name}'"
                        ),
                        constraints=constraints,
                        model=get_model(constraints),
                        pc=state.pc,
                    )
            enhanced_has_attr = _enhanced_object_has_attribute(enhanced_obj, attr_name)
            if enhanced_has_attr is True:
                return None
            if enhanced_has_attr is False and not _has_dynamic_attribute_hook(enhanced_obj):
                constraints = list(state.path_constraints)
                if not _solver_check(constraints):
                    return None
                return Issue(
                    kind=IssueKind.ATTRIBUTE_ERROR,
                    message=(
                        f"Possible AttributeError: '{obj.name}' may not have attribute "
                        f"'{attr_name}'"
                    ),
                    constraints=constraints,
                    model=get_model(constraints),
                    pc=state.pc,
                )
            invalid_conditions = _collect_invalid_attr_conditions(obj, attr_name)
            if not invalid_conditions:
                return None
            constraints = [*state.path_constraints, z3.Or(*invalid_conditions)]
            if not _solver_check(constraints):
                return None
            return Issue(
                kind=IssueKind.ATTRIBUTE_ERROR,
                message=f"Possible AttributeError: '{obj.name}' may not have attribute '{attr_name}'",
                constraints=constraints,
                model=get_model(constraints),
                pc=state.pc,
            )

        if _has_attribute_in_concrete_types(obj, attr_name):
            return None
        constraints = list(state.path_constraints)
        if not _solver_check(constraints):
            return None
        return Issue(
            kind=IssueKind.ATTRIBUTE_ERROR,
            message=f"Possible AttributeError: '{type(obj).__name__}' has no attribute '{attr_name}'",
            constraints=constraints,
            model=get_model(constraints),
            pc=state.pc,
        )
