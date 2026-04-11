# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Object Model Core for pysymex.
Phase 19: Logic for object model - built-in classes, state management,
attribute access protocol, and instance creation.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import z3

from pysymex.core.objects.types import (
    ObjectId,
    SymbolicClass,
    SymbolicMethod,
    SymbolicObject,
    SymbolicProperty,
)

OBJECT_CLASS = SymbolicClass(name="object", qualname="object")
TYPE_CLASS = SymbolicClass(name="type", qualname="type", bases=(OBJECT_CLASS,))
TYPE_CLASS.metaclass = TYPE_CLASS
OBJECT_CLASS.metaclass = TYPE_CLASS
INT_CLASS = SymbolicClass(name="int", qualname="int", bases=(OBJECT_CLASS,))
FLOAT_CLASS = SymbolicClass(name="float", qualname="float", bases=(OBJECT_CLASS,))
BOOL_CLASS = SymbolicClass(name="bool", qualname="bool", bases=(INT_CLASS,))
STR_CLASS = SymbolicClass(name="str", qualname="str", bases=(OBJECT_CLASS,))
BYTES_CLASS = SymbolicClass(name="bytes", qualname="bytes", bases=(OBJECT_CLASS,))
LIST_CLASS = SymbolicClass(name="list", qualname="list", bases=(OBJECT_CLASS,))
TUPLE_CLASS = SymbolicClass(name="tuple", qualname="tuple", bases=(OBJECT_CLASS,))
DICT_CLASS = SymbolicClass(name="dict", qualname="dict", bases=(OBJECT_CLASS,))
SET_CLASS = SymbolicClass(name="set", qualname="set", bases=(OBJECT_CLASS,))
FROZENSET_CLASS = SymbolicClass(name="frozenset", qualname="frozenset", bases=(OBJECT_CLASS,))
NONETYPE_CLASS = SymbolicClass(name="NoneType", qualname="NoneType", bases=(OBJECT_CLASS,))
FUNCTION_CLASS = SymbolicClass(name="function", qualname="function", bases=(OBJECT_CLASS,))
BUILTIN_CLASSES: dict[str, SymbolicClass] = {
    "object": OBJECT_CLASS,
    "type": TYPE_CLASS,
    "int": INT_CLASS,
    "float": FLOAT_CLASS,
    "bool": BOOL_CLASS,
    "str": STR_CLASS,
    "bytes": BYTES_CLASS,
    "list": LIST_CLASS,
    "tuple": TUPLE_CLASS,
    "dict": DICT_CLASS,
    "set": SET_CLASS,
    "frozenset": FROZENSET_CLASS,
    "NoneType": NONETYPE_CLASS,
    "function": FUNCTION_CLASS,
}


def get_builtin_class(name: str) -> SymbolicClass | None:
    """Get a built-in class by name."""
    return BUILTIN_CLASSES.get(name)


def get_class_for_value(value: object) -> SymbolicClass:
    """Get the SymbolicClass for a Python value."""
    match value:
        case None:
            return NONETYPE_CLASS
        case bool():
            return BOOL_CLASS
        case int():
            return INT_CLASS
        case float():
            return FLOAT_CLASS
        case str():
            return STR_CLASS
        case bytes():
            return BYTES_CLASS
        case list():
            return LIST_CLASS
        case tuple():
            return TUPLE_CLASS
        case dict():
            return DICT_CLASS
        case set():
            return SET_CLASS
        case frozenset():
            return FROZENSET_CLASS
        case _ if callable(value):
            return FUNCTION_CLASS
        case _:
            return OBJECT_CLASS


@dataclass(slots=True)
class ObjectState:
    """
    Tracks all objects in symbolic execution.
    This is part of the VM state and tracks:
    - All created objects
    - Object-class relationships
    - Identity comparisons
    """

    objects: dict[ObjectId, SymbolicObject] = field(
        default_factory=lambda: dict[ObjectId, SymbolicObject]()
    )
    classes: dict[str, SymbolicClass] = field(default_factory=lambda: dict[str, SymbolicClass]())
    _objects_shared: bool = False
    _classes_shared: bool = False

    def __post_init__(self) -> None:
        if not self.classes:
            for name, cls in BUILTIN_CLASSES.items():
                self.classes[name] = cls

    def create_object(
        self,
        cls: SymbolicClass,
        name: str | None = None,
    ) -> SymbolicObject:
        """Create a new symbolic object."""
        if self._objects_shared:
            self.objects = dict(self.objects)
            self._objects_shared = False
        obj = SymbolicObject(cls=cls, _id=ObjectId(name) if name else None)
        self.objects[obj.id] = obj
        return obj

    def create_class(
        self,
        name: str,
        bases: tuple[SymbolicClass, ...] = (),
        qualname: str = "",
    ) -> SymbolicClass:
        """Create a new symbolic class."""
        if self._classes_shared:
            self.classes = dict(self.classes)
            self._classes_shared = False
        if not bases:
            bases = (OBJECT_CLASS,)
        cls = SymbolicClass(name=name, qualname=qualname or name, bases=bases)
        self.classes[name] = cls
        return cls

    def get_object(self, obj_id: ObjectId) -> SymbolicObject | None:
        """Get an object by ID."""
        return self.objects.get(obj_id)

    def get_class(self, name: str) -> SymbolicClass | None:
        """Get a class by name."""
        return self.classes.get(name)

    def isinstance_check(
        self,
        obj: SymbolicObject,
        cls: SymbolicClass,
    ) -> z3.BoolRef:
        """Generate Z3 constraint for isinstance check."""
        if obj.isinstance_of(cls):
            return z3.BoolVal(True)
        return z3.BoolVal(False)

    def identity_equal(
        self,
        obj1: SymbolicObject,
        obj2: SymbolicObject,
    ) -> z3.BoolRef:
        """Generate Z3 constraint for identity comparison (is)."""
        return obj1.id.to_z3() == obj2.id.to_z3()

    def clone(self) -> ObjectState:
        """Create a copy-on-write clone of object state.

        Clones share dict storage until either clone mutates via
        ``create_object``/``create_class``, which materialize an independent
        copy before write.
        """
        self._objects_shared = True
        self._classes_shared = True
        state = object.__new__(ObjectState)
        state.objects = self.objects
        state.classes = self.classes
        state._objects_shared = True
        state._classes_shared = True
        return state


def getattr_symbolic(
    obj: SymbolicObject,
    name: str,
    default: object = None,
) -> tuple[object, bool]:
    """
    Symbolic getattr with descriptor protocol.
    Returns (value, found).
    """
    attr = obj.get_attribute(name)
    if attr is None or not attr.is_present():
        return default, default is not None
    value = attr.value
    if attr.is_property and isinstance(value, SymbolicProperty):
        return value.__get__(obj, obj.cls), True
    if attr.is_method:
        if isinstance(value, SymbolicMethod):
            if not value.is_bound:
                return value.bind(obj), True
            return value, True
        return SymbolicMethod(value, obj, obj.cls), True
    return value, True


def setattr_symbolic(
    obj: SymbolicObject,
    name: str,
    value: object,
) -> bool:
    """
    Symbolic setattr with descriptor protocol.
    Returns True if successful.
    """
    class_attr = obj.cls.lookup_attribute(name)
    if class_attr and class_attr.is_property:
        prop = class_attr.value
        if isinstance(prop, SymbolicProperty) and prop.fset is not None:
            prop.__set__(obj, value)
            return True
    obj.set_attribute(name, value)
    return True


def delattr_symbolic(
    obj: SymbolicObject,
    name: str,
) -> bool:
    """
    Symbolic delattr with descriptor protocol.
    Returns True if successful.
    """
    class_attr = obj.cls.lookup_attribute(name)
    if class_attr and class_attr.is_property:
        prop = class_attr.value
        if isinstance(prop, SymbolicProperty) and prop.fdel is not None:
            prop.__delete__(obj)
            return True
    return obj.delete_attribute(name)


def hasattr_symbolic(
    obj: SymbolicObject,
    name: str,
) -> z3.BoolRef:
    """
    Symbolic hasattr check.
    Returns Z3 boolean for whether attribute exists.
    """
    if obj.has_attribute(name):
        return z3.BoolVal(True)
    return z3.BoolVal(False)


def isinstance_symbolic(
    obj: SymbolicObject,
    classinfo: SymbolicClass | tuple[SymbolicClass, ...],
) -> z3.BoolRef:
    """Symbolic isinstance check."""
    if isinstance(classinfo, SymbolicClass):
        classes = (classinfo,)
    else:
        classes = classinfo
    for cls in classes:
        if obj.isinstance_of(cls):
            return z3.BoolVal(True)
    return z3.BoolVal(False)


def issubclass_symbolic(
    cls: SymbolicClass,
    classinfo: SymbolicClass | tuple[SymbolicClass, ...],
) -> z3.BoolRef:
    """Symbolic issubclass check."""
    if isinstance(classinfo, SymbolicClass):
        classes = (classinfo,)
    else:
        classes = classinfo
    for parent in classes:
        if cls.is_subclass_of(parent):
            return z3.BoolVal(True)
    return z3.BoolVal(False)


def type_of(obj: SymbolicObject) -> SymbolicClass:
    """Get the type (class) of an object."""
    return obj.cls


def create_instance(
    cls: SymbolicClass,
    state: ObjectState,
    init_attrs: dict[str, object] | None = None,
) -> SymbolicObject:
    """
    Create a new instance of a class.
    This is a simplified version - real instantiation would:
    1. Call __new__ to create instance
    2. Call __init__ to initialize
    """
    obj = state.create_object(cls)
    if init_attrs:
        for name, value in init_attrs.items():
            obj.set_attribute(name, value)
    return obj


def call_method(
    obj: SymbolicObject,
    method_name: str,
    args: tuple[object, ...] = (),
    kwargs: dict[str, object] | None = None,
) -> tuple[object, bool]:
    """
    Call a method on an object.
    Returns (result, found).
    """
    attr = obj.get_attribute(method_name)
    if attr is None or not attr.is_present():
        return None, False
    value, _ = getattr_symbolic(obj, method_name)
    if isinstance(value, SymbolicMethod):
        return None, True
    return None, False
