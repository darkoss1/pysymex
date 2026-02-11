"""
Object Model for PySpectre.
Phase 19: Classes, instances, and inheritance for symbolic execution.
This module provides:
- SymbolicObject: Represents a symbolic Python object
- SymbolicClass: Represents a symbolic Python class/type
- SymbolicMethod: Bound/unbound method handling
- SymbolicProperty: Property descriptor support
- MRO: Method Resolution Order computation
- ObjectState: Object attribute tracking
Classes and objects need special handling in symbolic execution
because attributes can be added dynamically.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)
import z3


class ObjectId:
    """
    Unique identifier for symbolic objects.
    Used to track object identity in the symbolic heap.
    """

    _counter: int = 0

    def __init__(self, name: str | None = None):
        ObjectId._counter += 1
        self._id = ObjectId._counter
        self._name = name or f"obj_{self._id}"
        self._z3_id = z3.Int(f"id_{self._name}")

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    def to_z3(self) -> z3.ArithRef:
        """Get Z3 representation for identity comparisons."""
        return self._z3_id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ObjectId):
            return self._id == other._id
        return False

    def __hash__(self) -> int:
        return hash(self._id)

    def __str__(self) -> str:
        return self._name

    def __repr__(self) -> str:
        return f"ObjectId({self._name})"


class AttributeState(Enum):
    """State of an object attribute."""

    CONCRETE = auto()
    SYMBOLIC = auto()
    DELETED = auto()
    UNKNOWN = auto()


@dataclass
class SymbolicAttribute:
    """
    A symbolic object attribute.
    Attributes can be:
    - Concrete: Known value
    - Symbolic: Unknown value with constraints
    - Deleted: Was deleted
    - Unknown: May or may not exist
    """

    name: str
    value: Any
    state: AttributeState = AttributeState.CONCRETE
    defined_in: str | None = None
    is_class_attr: bool = False
    is_method: bool = False
    is_property: bool = False

    @classmethod
    def concrete(cls, name: str, value: Any) -> SymbolicAttribute:
        """Create a concrete attribute."""
        return cls(name=name, value=value, state=AttributeState.CONCRETE)

    @classmethod
    def symbolic(cls, name: str, value: Any) -> SymbolicAttribute:
        """Create a symbolic attribute."""
        return cls(name=name, value=value, state=AttributeState.SYMBOLIC)

    @classmethod
    def deleted(cls, name: str) -> SymbolicAttribute:
        """Create a deleted attribute marker."""
        return cls(name=name, value=None, state=AttributeState.DELETED)

    @classmethod
    def unknown(cls, name: str) -> SymbolicAttribute:
        """Create an unknown attribute marker."""
        return cls(name=name, value=None, state=AttributeState.UNKNOWN)

    def is_present(self) -> bool:
        """Check if attribute is present (not deleted/unknown)."""
        return self.state in (AttributeState.CONCRETE, AttributeState.SYMBOLIC)


@dataclass
class SymbolicClass:
    """
    Represents a symbolic Python class.
    Tracks:
    - Class name and qualified name
    - Base classes (for MRO)
    - Class attributes and methods
    - Metaclass
    """

    name: str
    qualname: str = ""
    bases: tuple[SymbolicClass, ...] = ()
    metaclass: SymbolicClass | None = None
    attributes: dict[str, SymbolicAttribute] = field(default_factory=dict)
    _mro: tuple[SymbolicClass, ...] | None = None
    _id: ObjectId | None = None

    def __post_init__(self):
        if not self.qualname:
            self.qualname = self.name
        if self._id is None:
            self._id = ObjectId(f"class_{self.name}")

    @property
    def id(self) -> ObjectId:
        return self._id

    @property
    def mro(self) -> tuple[SymbolicClass, ...]:
        """Compute or return cached Method Resolution Order."""
        if self._mro is None:
            self._mro = self._compute_mro()
        return self._mro

    def _compute_mro(self) -> tuple[SymbolicClass, ...]:
        """Compute MRO using C3 linearization."""
        return compute_mro(self)

    def get_attribute(self, name: str) -> SymbolicAttribute | None:
        """Get a class attribute."""
        return self.attributes.get(name)

    def set_attribute(self, name: str, value: Any) -> None:
        """Set a class attribute."""
        self.attributes[name] = SymbolicAttribute.concrete(name, value)

    def has_attribute(self, name: str) -> bool:
        """Check if class has attribute."""
        return name in self.attributes and self.attributes[name].is_present()

    def lookup_attribute(self, name: str) -> SymbolicAttribute | None:
        """Lookup attribute through MRO."""
        for cls in self.mro:
            if cls.has_attribute(name):
                return cls.get_attribute(name)
        return None

    def is_subclass_of(self, other: SymbolicClass) -> bool:
        """Check if this class is a subclass of other."""
        return other in self.mro

    def __str__(self) -> str:
        return f"<class '{self.qualname}'>"

    def __repr__(self) -> str:
        return f"SymbolicClass({self.name!r})"


def compute_mro(cls: SymbolicClass) -> tuple[SymbolicClass, ...]:
    """
    Compute Method Resolution Order using C3 linearization.
    C3 linearization ensures:
    1. Children precede parents
    2. Parents maintain their order
    3. Consistent linearization across inheritance
    """
    if not cls.bases:
        return (cls,)

    def merge(seqs: list[list[SymbolicClass]]) -> list[SymbolicClass]:
        result = []
        while True:
            seqs = [s for s in seqs if s]
            if not seqs:
                return result
            for seq in seqs:
                head = seq[0]
                in_tail = any(head in s[1:] for s in seqs)
                if not in_tail:
                    result.append(head)
                    for s in seqs:
                        if s and s[0] == head:
                            s.pop(0)
                    break
            else:
                raise TypeError(f"Cannot create consistent MRO for {cls.name}")
        return result

    parent_mros = [list(base.mro) for base in cls.bases]
    parent_list = list(cls.bases)
    mro = merge([list([cls])] + parent_mros + [parent_list])
    return tuple(mro)


@dataclass
class SymbolicObject:
    """
    Represents a symbolic Python object instance.
    Tracks:
    - Object class
    - Instance attributes (__dict__)
    - Object identity
    - Slot values (if __slots__ defined)
    """

    cls: SymbolicClass
    attributes: dict[str, SymbolicAttribute] = field(default_factory=dict)
    _id: ObjectId | None = None
    slots: tuple[str, ...] | None = None

    def __post_init__(self):
        if self._id is None:
            self._id = ObjectId(f"inst_{self.cls.name}")

    @property
    def id(self) -> ObjectId:
        return self._id

    def get_attribute(
        self,
        name: str,
        check_class: bool = True,
    ) -> SymbolicAttribute | None:
        """
        Get an attribute, checking instance then class.
        Python attribute lookup order:
        1. Data descriptors in type(obj).__mro__
        2. Instance __dict__
        3. Non-data descriptors / class attrs in type(obj).__mro__
        For symbolic execution, we simplify to:
        1. Instance attributes
        2. Class attributes via MRO
        """
        if name in self.attributes:
            attr = self.attributes[name]
            if attr.is_present():
                return attr
        if check_class:
            return self.cls.lookup_attribute(name)
        return None

    def set_attribute(self, name: str, value: Any) -> None:
        """Set an instance attribute."""
        if self.slots is not None and name not in self.slots:
            pass
        self.attributes[name] = SymbolicAttribute.concrete(name, value)

    def delete_attribute(self, name: str) -> bool:
        """Delete an instance attribute."""
        if name in self.attributes:
            self.attributes[name] = SymbolicAttribute.deleted(name)
            return True
        return False

    def has_attribute(self, name: str, check_class: bool = True) -> bool:
        """Check if object has attribute."""
        attr = self.get_attribute(name, check_class)
        return attr is not None and attr.is_present()

    def get_class(self) -> SymbolicClass:
        """Get the object's class."""
        return self.cls

    def isinstance_of(self, other_cls: SymbolicClass) -> bool:
        """Check if object is instance of class."""
        return self.cls.is_subclass_of(other_cls)

    def __str__(self) -> str:
        return f"<{self.cls.qualname} object at {self._id}>"

    def __repr__(self) -> str:
        return f"SymbolicObject({self.cls.name!r}, {self._id})"


@dataclass
class SymbolicMethod:
    """
    Represents a bound or unbound method.
    In Python:
    - Unbound: function accessed on class
    - Bound: function accessed on instance (has __self__)
    """

    func: Any
    instance: SymbolicObject | None = None
    owner: SymbolicClass | None = None

    @property
    def is_bound(self) -> bool:
        return self.instance is not None

    @property
    def __self__(self) -> SymbolicObject | None:
        return self.instance

    @property
    def __func__(self) -> Any:
        return self.func

    def bind(self, instance: SymbolicObject) -> SymbolicMethod:
        """Create a bound method."""
        return SymbolicMethod(
            func=self.func,
            instance=instance,
            owner=self.owner or instance.cls,
        )

    def __str__(self) -> str:
        if self.is_bound:
            return f"<bound method {self.func} of {self.instance}>"
        return f"<function {self.func}>"


@dataclass
class SymbolicProperty:
    """
    Represents a property descriptor.
    Properties are data descriptors with optional getter, setter, deleter.
    """

    fget: Any | None = None
    fset: Any | None = None
    fdel: Any | None = None
    doc: str | None = None
    name: str = ""

    def __get__(
        self,
        obj: SymbolicObject | None,
        objtype: SymbolicClass | None = None,
    ) -> Any:
        """Get property value."""
        if obj is None:
            return self
        if self.fget is None:
            raise AttributeError(f"property '{self.name}' has no getter")
        return self.fget

    def __set__(self, obj: SymbolicObject, value: Any) -> None:
        """Set property value."""
        if self.fset is None:
            raise AttributeError(f"property '{self.name}' has no setter")

    def __delete__(self, obj: SymbolicObject) -> None:
        """Delete property."""
        if self.fdel is None:
            raise AttributeError(f"property '{self.name}' has no deleter")

    def getter(self, fget: Any) -> SymbolicProperty:
        """Return property with new getter."""
        return SymbolicProperty(fget, self.fset, self.fdel, self.doc, self.name)

    def setter(self, fset: Any) -> SymbolicProperty:
        """Return property with new setter."""
        return SymbolicProperty(self.fget, fset, self.fdel, self.doc, self.name)

    def deleter(self, fdel: Any) -> SymbolicProperty:
        """Return property with new deleter."""
        return SymbolicProperty(self.fget, self.fset, fdel, self.doc, self.name)


@dataclass
class SymbolicSuper:
    """
    Represents super() for method resolution.
    super() returns a proxy that delegates to a parent class.
    """

    type_: SymbolicClass
    obj: SymbolicObject | None = None
    obj_type: SymbolicClass | None = None

    def __post_init__(self):
        if self.obj is not None and self.obj_type is None:
            self.obj_type = self.obj.cls

    def get_attribute(self, name: str) -> SymbolicAttribute | None:
        """
        Get attribute from parent class.
        Searches MRO starting after type_.
        """
        if self.obj_type is None:
            return None
        mro = self.obj_type.mro
        found = False
        for cls in mro:
            if found:
                if cls.has_attribute(name):
                    attr = cls.get_attribute(name)
                    if attr and attr.is_method and self.obj is not None:
                        method = SymbolicMethod(attr.value, owner=cls)
                        return SymbolicAttribute(
                            name=name,
                            value=method.bind(self.obj),
                            is_method=True,
                        )
                    return attr
            if cls == self.type_:
                found = True
        return None


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


def get_class_for_value(value: Any) -> SymbolicClass:
    """Get the SymbolicClass for a Python value."""
    if value is None:
        return NONETYPE_CLASS
    if isinstance(value, bool):
        return BOOL_CLASS
    if isinstance(value, int):
        return INT_CLASS
    if isinstance(value, float):
        return FLOAT_CLASS
    if isinstance(value, str):
        return STR_CLASS
    if isinstance(value, bytes):
        return BYTES_CLASS
    if isinstance(value, list):
        return LIST_CLASS
    if isinstance(value, tuple):
        return TUPLE_CLASS
    if isinstance(value, dict):
        return DICT_CLASS
    if isinstance(value, set):
        return SET_CLASS
    if isinstance(value, frozenset):
        return FROZENSET_CLASS
    if callable(value):
        return FUNCTION_CLASS
    return OBJECT_CLASS


@dataclass
class ObjectState:
    """
    Tracks all objects in symbolic execution.
    This is part of the VM state and tracks:
    - All created objects
    - Object-class relationships
    - Identity comparisons
    """

    objects: dict[ObjectId, SymbolicObject] = field(default_factory=dict)
    classes: dict[str, SymbolicClass] = field(default_factory=dict)

    def __post_init__(self):
        for name, cls in BUILTIN_CLASSES.items():
            self.classes[name] = cls

    def create_object(
        self,
        cls: SymbolicClass,
        name: str | None = None,
    ) -> SymbolicObject:
        """Create a new symbolic object."""
        obj = SymbolicObject(cls=cls)
        if name:
            obj._id = ObjectId(name)
        self.objects[obj.id] = obj
        return obj

    def create_class(
        self,
        name: str,
        bases: tuple[SymbolicClass, ...] = (),
        qualname: str = "",
    ) -> SymbolicClass:
        """Create a new symbolic class."""
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
        """Create a shallow copy of object state."""
        state = ObjectState()
        state.objects = dict(self.objects)
        state.classes = dict(self.classes)
        return state


def getattr_symbolic(
    obj: SymbolicObject,
    name: str,
    default: Any = None,
) -> tuple[Any, bool]:
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
    value: Any,
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
    init_attrs: dict[str, Any] | None = None,
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
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
) -> tuple[Any, bool]:
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
