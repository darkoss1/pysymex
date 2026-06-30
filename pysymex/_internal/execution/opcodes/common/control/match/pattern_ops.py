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

"""``MATCH_*`` pattern operations for mapping, sequence, and class patterns.

Resolves concrete and modeled capture tuples, builtin type guards, and class MRO
checks used by :mod:`pysymex._internal.execution.opcodes.common.control.match`. Does not fork
paths; callers combine results with branch opcodes.
"""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


MATCH_CLASS_ATTR_PROTOCOL = "__match_class_attr__"


@dataclass(frozen=True, slots=True)
class MatchClassAttrContinuation:
    """Retained state while a class pattern executes a property getter."""

    receiver: SymbolicValue
    attr_names: tuple[str, ...]
    captured: tuple[StackValue, ...]
    next_index: int


class MatchPatternOps:
    """Domain owner for structural pattern-match capture and class-pattern flow."""

    @staticmethod
    def subject(subject: object, state: VMState) -> object:
        """Resolve heap-backed symbolic object handles for pattern matching tests."""
        if isinstance(subject, SymbolicObject) and subject.address != -1:
            return state.memory.get(subject.address, subject)
        return subject

    @staticmethod
    def keys(keys_tuple: object) -> list[object] | None:
        """Return concrete key objects from a ``MATCH_KEYS`` keys tuple when known."""
        if isinstance(keys_tuple, SymbolicList) and keys_tuple.concrete_items is not None:
            return keys_tuple.concrete_items
        if isinstance(keys_tuple, tuple):
            return list(cast("tuple[object, ...]", keys_tuple))
        if isinstance(keys_tuple, list):
            return list(cast("list[object]", keys_tuple))
        return None

    @staticmethod
    def concrete_key_values(subject: object, keys_tuple: object) -> tuple[StackValue, ...] | None:
        """Return definite mapping-pattern captures without inventing value types."""
        keys = MatchPatternOps.keys(keys_tuple)
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

    @staticmethod
    def class_attr_names(class_obj: type, names_tuple: object, positional: int) -> list[str] | None:
        """Decode ``__match_args__`` and keyword names for a concrete class pattern."""
        keywords_obj = MatchPatternOps.keys(names_tuple)
        if keywords_obj is None:
            return None

        keywords: list[str] = []
        for item in keywords_obj:
            if not isinstance(item, str):
                return None
            keywords.append(item)

        positional_names: list[str]
        if class_obj in MatchPatternOps.MATCH_SELF_TYPES:
            if positional > 1:
                return None
            positional_names = ["__match_self__"] if positional else []
        else:
            match_args_obj = getattr(class_obj, "__match_args__", ())
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

    @staticmethod
    def builtin_match_success(subject: SymbolicValue, class_obj: type) -> z3.BoolRef | None:
        """Return a type guard for builtin ``MATCH_CLASS`` patterns, or ``None`` if unsupported."""
        if class_obj is bool:
            return subject.is_bool
        if class_obj is int:
            return z3.Or(subject.is_int, subject.is_bool)
        if class_obj is float:
            return subject.is_float
        if class_obj is str:
            return subject.is_str
        if class_obj in (list, tuple):
            return subject.is_list
        if class_obj is dict:
            return subject.is_dict
        if class_obj is object:
            return Z3_TRUE
        if class_obj is type(None):
            return subject.is_none
        return None

    @staticmethod
    def concrete_class_attrs(
        subject: object,
        cls: type,
        names_tuple: object,
        positional: int,
    ) -> tuple[StackValue, ...] | SymbolicNoneType | None:
        """Extract concrete class-pattern capture values or a non-match sentinel."""
        attr_names = MatchPatternOps.class_attr_names(cls, names_tuple, positional)
        if attr_names is None:
            return None
        if not isinstance(subject, cls):
            return SymbolicNoneType("match_class_no_match")

        attrs: list[StackValue] = []
        for name in attr_names:
            if name == "__match_self__":
                attrs.append(cast("StackValue", subject))
                continue
            try:
                attrs.append(cast("StackValue", getattr(subject, name)))
            except AttributeError:
                return SymbolicNoneType("match_class_missing_attr")
        return tuple(attrs)

    @staticmethod
    def class_from_pattern(class_obj: object) -> object | None:
        """Resolve a modeled class object from a ``MATCH_CLASS`` pattern operand."""
        if (
            isinstance(class_obj, type)
            and class_obj not in MatchPatternOps.MATCH_SELF_TYPES
            and class_obj is not object
        ):
            try:
                from pysymex._internal.core.classes.registry import class_registry
                from pysymex._internal.execution.opcodes.common.functions.classes.registration import (
                    modeled_class_from_python_type,
                )
            except ImportError:
                return None

            modeled_cls = class_registry.get_class(class_obj.__name__)
            if modeled_cls is None or getattr(modeled_cls, "module", None) == "builtins":
                return None
            return modeled_class_from_python_type(class_obj)

        if (
            not isinstance(class_obj, SymbolicValue)
            or getattr(class_obj, "affinity_type", None) != "type"
        ):
            return None

        modeled_object = getattr(class_obj, "_modeled_object", None)
        try:
            from pysymex._internal.core.classes.classes import SymbolicClass
            from pysymex._internal.core.classes.registry import class_registry
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

    @staticmethod
    def object_from_subject(subject: object) -> object | None:
        """Return the modeled instance carried by a match subject when present."""
        modeled_object = getattr(subject, "_modeled_object", None)
        try:
            from pysymex._internal.core.classes.instances import SymbolicInstance
        except ImportError:
            return None

        if isinstance(modeled_object, SymbolicInstance):
            return modeled_object
        if isinstance(subject, SymbolicInstance):
            return subject
        return None

    @staticmethod
    def class_is_subclass(subject_class: object, pattern_class: object) -> bool | None:
        """Query modeled MRO when ``is_subclass_of`` is available on the subject class."""
        is_subclass_of = getattr(subject_class, "is_subclass_of", None)
        if callable(is_subclass_of):
            result = is_subclass_of(pattern_class)
            if isinstance(result, bool):
                return result
        return None

    @staticmethod
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

    @staticmethod
    def modeled_attr_names(
        modeled_cls: object,
        names_tuple: object,
        positional: int,
    ) -> list[str] | None:
        """Decode positional and keyword capture names for a modeled class pattern."""
        keywords_obj = MatchPatternOps.keys(names_tuple)
        if keywords_obj is None:
            return None

        keywords: list[str] = []
        for item in keywords_obj:
            if not isinstance(item, str):
                return None
            keywords.append(item)

        match_args = MatchPatternOps.modeled_match_args(modeled_cls)
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

    @staticmethod
    def modeled_class_attrs(
        subject: object,
        cls: object,
        names_tuple: object,
        positional: int,
    ) -> tuple[StackValue, ...] | SymbolicNoneType | None:
        """Extract modeled class-pattern captures using ``__match_args__`` when available."""
        subject_obj = MatchPatternOps.object_from_subject(subject)
        pattern_cls = MatchPatternOps.class_from_pattern(cls)
        if subject_obj is None or pattern_cls is None:
            return None

        subject_cls = getattr(subject_obj, "cls", None)
        match_result = MatchPatternOps.class_is_subclass(subject_cls, pattern_cls)
        if match_result is False:
            return SymbolicNoneType("match_class_no_match")
        if match_result is not True:
            return None

        attr_names = MatchPatternOps.modeled_attr_names(pattern_cls, names_tuple, positional)
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
            value: object = typed_attr[0]
            found: object = typed_attr[1]
            if not isinstance(found, bool) or not found:
                return SymbolicNoneType("match_class_missing_attr")
            attrs.append(cast("StackValue", value))
        return tuple(attrs)

    @staticmethod
    def dispatch_class_attrs(
        state: VMState,
        ctx: OpcodeDispatcher,
        subject: object,
        cls: object,
        names_tuple: object,
        positional: int,
    ) -> tuple[StackValue, ...] | SymbolicNoneType | OpcodeResult | None:
        """Extract modeled class-pattern captures, entering property getters when needed."""
        context = _modeled_match_context(subject, cls, names_tuple, positional)
        if context is None:
            return None
        if isinstance(context, SymbolicNoneType):
            return context
        receiver, attr_names = context
        return _resolve_modeled_match_attrs_from_index(
            state,
            ctx,
            receiver,
            attr_names,
            captured=(),
            start_index=0,
        )

    @staticmethod
    def complete_class_attr(
        frame: CallFrame,
        return_value: StackValue | None,
        state: VMState,
        ctx: OpcodeDispatcher,
    ) -> OpcodeResult | None:
        """Resume ``MATCH_CLASS`` after a retained property getter returns."""
        retained = frame.protocol_retained_operand
        if frame.protocol_method != MATCH_CLASS_ATTR_PROTOCOL or not isinstance(
            retained,
            MatchClassAttrContinuation,
        ):
            return None
        state.depth -= 1
        captured_value = (
            return_value if return_value is not None else SymbolicNoneType("match_attr_None")
        )
        result = _resolve_modeled_match_attrs_from_index(
            state,
            ctx,
            retained.receiver,
            retained.attr_names,
            captured=(*retained.captured, captured_value),
            start_index=retained.next_index,
        )
        if isinstance(result, OpcodeResult):
            return result
        if result is None:
            return None
        state = state.push(result)
        return OpcodeResult.continue_with(state)

    @staticmethod
    def class_attr_error(frame: CallFrame, state: VMState) -> VMState | None:
        """Return a no-match state when class-pattern attribute extraction raises AttributeError."""
        if frame.protocol_method != MATCH_CLASS_ATTR_PROTOCOL:
            return None
        return state.set_pc(frame.return_pc).push(SymbolicNoneType("match_class_missing_attr"))


def _modeled_match_context(
    subject: object,
    cls: object,
    names_tuple: object,
    positional: int,
) -> tuple[SymbolicValue, tuple[str, ...]] | SymbolicNoneType | None:
    if not isinstance(subject, SymbolicValue):
        return None
    subject_obj = MatchPatternOps.object_from_subject(subject)
    pattern_cls = MatchPatternOps.class_from_pattern(cls)
    if subject_obj is None or pattern_cls is None:
        return None

    subject_cls = getattr(subject_obj, "cls", None)
    match_result = MatchPatternOps.class_is_subclass(subject_cls, pattern_cls)
    if match_result is False:
        return SymbolicNoneType("match_class_no_match")
    if match_result is not True:
        return None

    attr_names = MatchPatternOps.modeled_attr_names(pattern_cls, names_tuple, positional)
    if attr_names is None:
        return None
    return subject, tuple(attr_names)


def _resolve_modeled_match_attrs_from_index(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_names: tuple[str, ...],
    *,
    captured: tuple[StackValue, ...],
    start_index: int,
) -> tuple[StackValue, ...] | SymbolicNoneType | OpcodeResult | None:
    subject_obj = MatchPatternOps.object_from_subject(receiver)
    if subject_obj is None:
        return None
    if not attr_names:
        return tuple(captured)
    get_attribute = getattr(subject_obj, "get_attribute", None)
    if not callable(get_attribute):
        return None

    attrs: list[StackValue] = list(captured)
    resume_pc = state.pc if start_index > 0 else None
    for index in range(start_index, len(attr_names)):
        name = attr_names[index]
        if _has_modeled_property(receiver, name):
            property_result = _dispatch_modeled_match_property_getter(
                state,
                ctx,
                receiver,
                name,
                attr_names,
                tuple(attrs),
                index + 1,
                resume_pc=resume_pc,
            )
            if property_result is not None:
                return property_result
            return None
        data_descriptor_result = _get_modeled_match_descriptor(
            state,
            ctx,
            receiver,
            name,
            attr_names,
            tuple(attrs),
            index + 1,
            data_descriptor=True,
            resume_pc=resume_pc,
        )
        if data_descriptor_result is not None:
            return data_descriptor_result
        raw_attr = get_attribute(name)
        if not isinstance(raw_attr, tuple):
            return None
        typed_attr = cast("tuple[object, ...]", raw_attr)
        if len(typed_attr) != 2:
            return None
        value: object = typed_attr[0]
        found: object = typed_attr[1]
        if not isinstance(found, bool) or not found:
            non_data_descriptor_result = _get_modeled_match_descriptor(
                state,
                ctx,
                receiver,
                name,
                attr_names,
                tuple(attrs),
                index + 1,
                data_descriptor=False,
                resume_pc=resume_pc,
            )
            if non_data_descriptor_result is not None:
                return non_data_descriptor_result
            return SymbolicNoneType("match_class_missing_attr")
        attrs.append(cast("StackValue", value))
    return tuple(attrs)


def _has_modeled_property(receiver: SymbolicValue, attr_name: str) -> bool:
    modeled_object = getattr(receiver, "_modeled_object", None)
    modeled_class = getattr(modeled_object, "cls", None)
    properties = getattr(modeled_class, "properties", None)
    return isinstance(properties, dict) and attr_name in properties


def _dispatch_modeled_match_property_getter(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    attr_names: tuple[str, ...],
    captured: tuple[StackValue, ...],
    next_index: int,
    resume_pc: int | None,
) -> OpcodeResult | None:
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.properties import (
        dispatch_modeled_property_getter,
    )

    return dispatch_modeled_property_getter(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=MATCH_CLASS_ATTR_PROTOCOL,
        protocol_retained_operand=cast(
            "StackValue",
            MatchClassAttrContinuation(
                receiver=receiver,
                attr_names=attr_names,
                captured=captured,
                next_index=next_index,
            ),
        ),
        resume_pc=resume_pc,
    )


def _get_modeled_match_descriptor(
    state: VMState,
    ctx: OpcodeDispatcher,
    receiver: SymbolicValue,
    attr_name: str,
    attr_names: tuple[str, ...],
    captured: tuple[StackValue, ...],
    next_index: int,
    *,
    data_descriptor: bool,
    resume_pc: int | None,
) -> OpcodeResult | None:
    from pysymex._internal.execution.opcodes.common.functions.attribute.descriptors.dispatch import (
        get_declared_data_descriptor,
        get_declared_non_data_descriptor,
    )

    dispatcher = (
        get_declared_data_descriptor if data_descriptor else get_declared_non_data_descriptor
    )
    return dispatcher(
        state,
        ctx,
        receiver,
        attr_name,
        protocol_method=MATCH_CLASS_ATTR_PROTOCOL,
        protocol_retained_operand=cast(
            "StackValue",
            MatchClassAttrContinuation(
                receiver=receiver,
                attr_names=attr_names,
                captured=captured,
                next_index=next_index,
            ),
        ),
        resume_pc=resume_pc,
    )
