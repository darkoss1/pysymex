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

"""``MATCH_*`` lowering helpers for mapping, sequence, and class patterns.

Resolves concrete and modeled capture tuples, builtin type guards, and class MRO
checks used by :mod:`pysymex.execution.opcodes.common.control.match`. Does not fork
paths; callers combine results with branch opcodes.
"""

from __future__ import annotations

import types
from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.constants import Z3_TRUE
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def resolve_match_subject(subject: object, state: VMState) -> object:
    """Resolve heap-backed symbolic object handles for pattern matching tests."""
    if isinstance(subject, SymbolicObject) and subject.address != -1:
        return state.memory.get(subject.address, subject)
    return subject


def extract_match_keys(keys_tuple: object) -> list[object] | None:
    """Return concrete key objects from a ``MATCH_KEYS`` keys tuple when known."""
    if isinstance(keys_tuple, SymbolicList) and keys_tuple.concrete_items is not None:
        return keys_tuple.concrete_items
    if isinstance(keys_tuple, tuple):
        return list(cast("tuple[object, ...]", keys_tuple))
    if isinstance(keys_tuple, list):
        return list(cast("list[object]", keys_tuple))
    return None


def concrete_match_key_values(
    subject: object, keys_tuple: object
) -> tuple["StackValue", ...] | None:
    """Return definite mapping-pattern captures without inventing value types."""
    keys = extract_match_keys(keys_tuple)
    if keys is None:
        return None

    values: list[StackValue] = []
    if isinstance(subject, SymbolicDict):
        for key in keys:
            found, value = subject.concrete_value_for_key(key)
            if not found:
                return None
            values.append(cast("StackValue", value))
        return tuple(values)

    if isinstance(subject, dict):
        concrete_subject = cast("dict[object, object]", subject)
        for key in keys:
            try:
                values.append(cast("StackValue", concrete_subject[key]))
            except (KeyError, TypeError):
                return None
        return tuple(values)
    return None


MATCH_SELF_TYPES = {
    bool,
    bytearray,
    bytes,
    dict,
    float,
    frozenset,
    int,
    list,
    set,
    str,
    tuple,
}


def extract_match_class_attr_names(
    cls: type, names_tuple: object, positional: int
) -> list[str] | None:
    """Decode ``__match_args__`` and keyword names for a concrete class pattern."""
    keywords_obj = extract_match_keys(names_tuple)
    if keywords_obj is None:
        return None

    keywords: list[str] = []
    for item in keywords_obj:
        if not isinstance(item, str):
            return None
        keywords.append(item)

    positional_names: list[str]
    if cls in MATCH_SELF_TYPES:
        if positional > 1:
            return None
        positional_names = ["__match_self__"] if positional else []
    else:
        match_args_obj = getattr(cls, "__match_args__", ())
        if not isinstance(match_args_obj, tuple):
            return None
        match_args = cast("tuple[object, ...]", match_args_obj)
        if positional > len(match_args):
            return None
        positional_names = []
        for item in match_args[:positional]:
            if not isinstance(item, str):
                return None
            positional_names.append(item)

    names = [*positional_names, *keywords]
    if len(set(names)) != len(names):
        return None
    return names


def builtin_match_success(subject: SymbolicValue, cls: type) -> z3.BoolRef | None:
    """Return a type guard for builtin ``MATCH_CLASS`` patterns, or ``None`` if unsupported."""
    if cls is bool:
        return subject.is_bool
    if cls is int:
        return z3.Or(subject.is_int, subject.is_bool)
    if cls is float:
        return subject.is_float
    if cls is str:
        return subject.is_str
    if cls in (list, tuple):
        return subject.is_list
    if cls is dict:
        return subject.is_dict
    if cls is object:
        return Z3_TRUE
    if cls is type(None):
        return subject.is_none
    return None


def concrete_match_class_attrs(
    subject: object, cls: type, names_tuple: object, positional: int
) -> tuple["StackValue", ...] | SymbolicNone | None:
    """Extract concrete class-pattern capture values or a non-match sentinel."""
    attr_names = extract_match_class_attr_names(cls, names_tuple, positional)
    if attr_names is None:
        return None
    if not isinstance(subject, cls):
        return SymbolicNone("match_class_no_match")

    attrs: list[StackValue] = []
    for name in attr_names:
        if name == "__match_self__":
            attrs.append(cast("StackValue", subject))
            continue
        try:
            attrs.append(cast("StackValue", getattr(subject, name)))
        except AttributeError:
            return SymbolicNone("match_class_missing_attr")
    return tuple(attrs)


def modeled_class_from_pattern(cls: object) -> object | None:
    """Resolve a modeled class object from a symbolic ``type`` pattern operand."""
    if not isinstance(cls, SymbolicValue) or getattr(cls, "affinity_type", None) != "type":
        return None

    modeled_object = getattr(cls, "_modeled_object", None)
    try:
        from pysymex.models.objects import SymbolicClass, class_registry
    except ImportError:
        return None

    if isinstance(modeled_object, SymbolicClass):
        return modeled_object
    if not isinstance(modeled_object, types.CodeType):
        return None

    modeled_cls = class_registry.get_by_code_object(modeled_object)
    if modeled_cls is not None:
        return modeled_cls
    return None


def modeled_object_from_subject(subject: object) -> object | None:
    """Return the modeled instance carried by a match subject when present."""
    modeled_object = getattr(subject, "_modeled_object", None)
    try:
        from pysymex.models.objects import SymbolicInstance
    except ImportError:
        return None

    if isinstance(modeled_object, SymbolicInstance):
        return modeled_object
    if isinstance(subject, SymbolicInstance):
        return subject
    return None


def modeled_class_is_subclass(subject_class: object, pattern_class: object) -> bool | None:
    """Query modeled MRO when ``is_subclass_of`` is available on the subject class."""
    is_subclass_of = getattr(subject_class, "is_subclass_of", None)
    if callable(is_subclass_of):
        result = is_subclass_of(pattern_class)
        if isinstance(result, bool):
            return result
    return None


def modeled_match_args(modeled_cls: object) -> tuple[str, ...] | None:
    """Read ``__match_args__`` from a modeled class when it is a tuple of strings."""
    class_vars = getattr(modeled_cls, "class_vars", None)
    if isinstance(class_vars, dict):
        typed_class_vars = cast("dict[str, object]", class_vars)
        value = typed_class_vars.get("__match_args__")
        if isinstance(value, tuple):
            typed_value = cast("tuple[object, ...]", value)
            if all(isinstance(item, str) for item in typed_value):
                return cast("tuple[str, ...]", typed_value)

    get_attribute = getattr(modeled_cls, "get_attribute", None)
    attr = get_attribute("__match_args__") if callable(get_attribute) else None
    value = getattr(attr, "value", None)
    if isinstance(value, tuple):
        typed_value = cast("tuple[object, ...]", value)
        if all(isinstance(item, str) for item in typed_value):
            return cast("tuple[str, ...]", typed_value)
    return None


def modeled_match_class_attr_names(
    modeled_cls: object, names_tuple: object, positional: int
) -> list[str] | None:
    """Decode positional and keyword capture names for a modeled class pattern."""
    keywords_obj = extract_match_keys(names_tuple)
    if keywords_obj is None:
        return None

    keywords: list[str] = []
    for item in keywords_obj:
        if not isinstance(item, str):
            return None
        keywords.append(item)

    match_args = modeled_match_args(modeled_cls)
    if positional:
        if match_args is None or positional > len(match_args):
            return None
        positional_names = list(match_args[:positional])
    else:
        positional_names = []

    names = [*positional_names, *keywords]
    if len(set(names)) != len(names):
        return None
    return names


def modeled_match_class_attrs(
    subject: object, cls: object, names_tuple: object, positional: int
) -> tuple["StackValue", ...] | SymbolicNone | None:
    """Extract modeled class-pattern captures using ``__match_args__`` when available."""
    subject_obj = modeled_object_from_subject(subject)
    pattern_cls = modeled_class_from_pattern(cls)
    if subject_obj is None or pattern_cls is None:
        return None

    subject_cls = getattr(subject_obj, "cls", None)
    match_result = modeled_class_is_subclass(subject_cls, pattern_cls)
    if match_result is False:
        return SymbolicNone("match_class_no_match")
    if match_result is not True:
        return None

    attr_names = modeled_match_class_attr_names(pattern_cls, names_tuple, positional)
    if attr_names is None:
        return None

    attrs: list[StackValue] = []
    get_attribute = getattr(subject_obj, "get_attribute", None)
    if not callable(get_attribute):
        return None
    for name in attr_names:
        raw_attr = get_attribute(name)
        if not isinstance(raw_attr, tuple):
            return None
        typed_attr = cast("tuple[object, ...]", raw_attr)
        if len(typed_attr) != 2:
            return None
        value, found = typed_attr
        if not isinstance(found, bool) or not found:
            return SymbolicNone("match_class_missing_attr")
        attrs.append(cast("StackValue", value))
    return tuple(attrs)
