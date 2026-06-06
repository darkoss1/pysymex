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
    ``AttributeError`` — an attribute access on a primitive, symbolic, or
    modeled object that is provably absent or read-only.

Evidence:
    Satisfiable path constraints where the object's type does not expose
    the requested attribute.

Issue kind:
    ``IssueKind.ATTRIBUTE_ERROR``.
"""

from __future__ import annotations

import dis
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

import z3
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.core.types.havoc import is_havoc
from pysymex.models.stdlib.pathlib.core import PATH_STRING_ATTRIBUTE_NAMES, PATH_STRING_PREFIXES
from pysymex.analysis.detectors.detector.contract import Detector
from pysymex.analysis.detectors.detector.types import IsSatFn, Issue, IssueKind
from pysymex.analysis.detectors.feasibility import get_model_if_satisfiable

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
    "bytearray": frozenset(dir(bytearray)),
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
        bytearray,
    )
    for concrete_type in candidate_types:
        if isinstance(obj, concrete_type):
            return attr_name in _BUILTIN_ATTRS_BY_KIND[concrete_type.__name__]
    try:
        return hasattr(obj, attr_name)
    except Exception:
        return True


def _symbolic_container_kind(obj: object, state: VMState) -> str | None:
    """Resolve symbolic container wrappers to their Python container kind."""
    if isinstance(obj, SymbolicString):
        return "str"
    if isinstance(obj, SymbolicBytes):
        return "bytes"
    if isinstance(obj, SymbolicList):
        return _symbolic_list_kind(obj)
    if isinstance(obj, SymbolicDict):
        return "dict"
    if isinstance(obj, SymbolicObject):
        obj_state = state.memory.get(obj.address)
        if isinstance(obj_state, SymbolicList):
            return _symbolic_list_kind(obj_state)
        if isinstance(obj_state, SymbolicDict):
            return "dict"
    if isinstance(obj, SymbolicValue):
        modeled_object = getattr(obj, "_modeled_object", None)
        if isinstance(modeled_object, SymbolicList):
            return _symbolic_list_kind(modeled_object)
        if obj.affinity_type in _BUILTIN_ATTRS_BY_KIND:
            return obj.affinity_type
        if getattr(obj, "_type", None) in _BUILTIN_ATTRS_BY_KIND:
            return str(getattr(obj, "_type"))
    return None


def _symbolic_list_kind(obj: SymbolicList) -> str:
    type_marker = getattr(obj, "_type", None)
    if isinstance(type_marker, str) and type_marker in _BUILTIN_ATTRS_BY_KIND:
        return type_marker
    return "list"


def _is_modeled_symbolic_path_attribute(obj: object, attr_name: str) -> bool:
    """Return ``True`` if *attr_name* is a supported path-like synthetic attribute for *obj*."""
    return (
        isinstance(obj, SymbolicString)
        and attr_name in PATH_STRING_ATTRIBUTE_NAMES
        and obj.name.startswith(PATH_STRING_PREFIXES)
    )


def _is_abstract_generator_protocol_attribute(obj: object, attr_name: str) -> bool:
    """Return whether an opaque generator is guaranteed to expose an attribute."""
    return (
        isinstance(obj, SymbolicIterator)
        and obj.is_generator
        and attr_name in {"__iter__", "__next__", "close", "send", "throw"}
    )


def _has_dynamic_attribute_hook(obj: object) -> bool:
    """Return ``True`` if *obj* is an opaque generator guaranteed to expose *attr_name*."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


def _modeled_object_has_attribute(obj: object, attr_name: str) -> bool | None:
    """Return ``True``/``False`` if the modeled MRO declares *attr_name*, ``None`` if unknown."""
    modeled_class = getattr(obj, "cls", None)
    for candidate in getattr(modeled_class, "mro", ()):
        bindings = getattr(candidate, "_pysymex_declared_descriptors", None)
        if isinstance(bindings, dict) and attr_name in bindings:
            return True
    get_attribute = cast(
        "Callable[[str], tuple[object, bool]] | None",
        getattr(obj, "get_attribute", None),
    )
    if not callable(get_attribute):
        return None
    _, found = get_attribute(attr_name)
    return bool(found)


def _modeled_object_can_store_attribute(obj: object, attr_name: str) -> bool:
    """Return ``True`` if *attr_name* can be written on the modeled *obj*."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if callable(get_method) and get_method("__setattr__") is not None:
        return True
    properties_obj = getattr(modeled_class, "properties", {})
    if isinstance(properties_obj, dict) and attr_name in properties_obj:
        properties = cast("dict[str, object]", properties_obj)
        prop = properties[attr_name]
        return getattr(prop, "fset", None) is not None
    slots = getattr(modeled_class, "slots", None)
    return slots is None or attr_name in slots


def _modeled_object_can_delete_attribute(obj: object) -> bool:
    """Return ``True`` if modeled ``__delattr__`` owns delete semantics."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    return callable(get_method) and get_method("__delattr__") is not None


def _modeled_object_has_readonly_property(obj: object, attr_name: str) -> bool:
    """Return ``True`` if *attr_name* is a read-only property on the modeled *obj*."""
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    properties_obj = getattr(modeled_class, "properties", {})
    if not isinstance(properties_obj, dict) or attr_name not in properties_obj:
        return False
    properties = cast("dict[str, object]", properties_obj)
    return getattr(properties[attr_name], "fset", None) is None


class AttributeErrorDetector(Detector):
    """Detect ``AttributeError`` exceptions on attribute loads, stores, and deletes.

    Bug class:
        ``AttributeError`` — an attribute lookup or write that is provably
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
    relevant_opcodes = frozenset({"LOAD_ATTR", "STORE_ATTR", "DELETE_ATTR", "LOAD_SUPER_ATTR"})

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
        if _is_modeled_symbolic_path_attribute(obj, attr_name):
            return None
        if _is_abstract_generator_protocol_attribute(obj, attr_name):
            return None
        container_kind = _symbolic_container_kind(obj, state)
        if container_kind is not None and attr_name in _BUILTIN_ATTRS_BY_KIND[container_kind]:
            return None

        if isinstance(obj, SymbolicObject):
            return None

        if isinstance(obj, SymbolicValue):
            if obj.name.startswith(_INTERNAL_SYMBOLIC_ATTR_PREFIXES):
                return None
            modeled_object = getattr(obj, "_modeled_object", None)
            if instruction.opname == "STORE_ATTR":
                if _modeled_object_can_store_attribute(modeled_object, attr_name):
                    return None
                if _modeled_object_has_readonly_property(modeled_object, attr_name):
                    constraints = list(state.path_constraints)
                    model = get_model_if_satisfiable(constraints, _solver_check)
                    if model is None:
                        return None
                    return Issue(
                        kind=IssueKind.ATTRIBUTE_ERROR,
                        message=(
                            f"Possible AttributeError: '{obj.name}' may not have writable "
                            f"attribute '{attr_name}'"
                        ),
                        constraints=constraints,
                        model=model,
                        pc=state.pc,
                    )
            if instruction.opname == "DELETE_ATTR" and _modeled_object_can_delete_attribute(
                modeled_object
            ):
                return None
            modeled_has_attr = _modeled_object_has_attribute(modeled_object, attr_name)
            if modeled_has_attr is True:
                return None
            if modeled_has_attr is False and not _has_dynamic_attribute_hook(modeled_object):
                constraints = list(state.path_constraints)
                model = get_model_if_satisfiable(constraints, _solver_check)
                if model is None:
                    return None
                return Issue(
                    kind=IssueKind.ATTRIBUTE_ERROR,
                    message=(
                        f"Possible AttributeError: '{obj.name}' may not have attribute "
                        f"'{attr_name}'"
                    ),
                    constraints=constraints,
                    model=model,
                    pc=state.pc,
                )
            invalid_conditions = _collect_invalid_attr_conditions(obj, attr_name)
            if not invalid_conditions:
                return None
            constraints = [*state.path_constraints, z3.Or(*invalid_conditions)]
            model = get_model_if_satisfiable(constraints, _solver_check)
            if model is None:
                return None
            return Issue(
                kind=IssueKind.ATTRIBUTE_ERROR,
                message=f"Possible AttributeError: '{obj.name}' may not have attribute '{attr_name}'",
                constraints=constraints,
                model=model,
                pc=state.pc,
            )

        if _has_attribute_in_concrete_types(obj, attr_name):
            return None
        constraints = list(state.path_constraints)
        model = get_model_if_satisfiable(constraints, _solver_check)
        if model is None:
            return None
        return Issue(
            kind=IssueKind.ATTRIBUTE_ERROR,
            message=f"Possible AttributeError: '{type(obj).__name__}' has no attribute '{attr_name}'",
            constraints=constraints,
            model=model,
            pc=state.pc,
        )
