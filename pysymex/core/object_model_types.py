"""
Object Model Types for pysymex.
Phase 19: Classes, instances, and inheritance for symbolic execution.
This module provides the data types:
- ObjectId: Unique identifier for symbolic objects
- AttributeState: Enum for attribute states
- SymbolicAttribute: Symbolic object attribute
- SymbolicClass: Symbolic Python class/type
- SymbolicObject: Symbolic Python object instance
- SymbolicMethod: Bound/unbound method handling
- SymbolicProperty: Property descriptor support
- SymbolicSuper: super() proxy
- compute_mro: C3 linearization for MRO
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)

import z3


class ObjectId:
    """Unique identifier for symbolic objects in the heap.

    Each ``ObjectId`` pairs a monotonic integer ID with a Z3 integer
    expression, enabling both fast Python-level identity checks and
    symbolic identity reasoning.

    Attributes:
        _id: Monotonic integer counter value.
        _name: Human-readable name (e.g. ``"obj_3"``).
        _z3_id: Lazily-created Z3 integer expression for symbolic comparisons.
    """

    _counter: int = 0
    _counter_lock = threading.Lock()
    __slots__ = ("_id", "_name", "_z3_id", "_z3_lock")

    def __init__(self, name: str | None = None):
        """Init."""
        """Initialize the class instance."""
        with ObjectId._counter_lock:
            ObjectId._counter += 1
            self._id = ObjectId._counter
        self._name = name or f"obj_{self._id}"
        self._z3_id: z3.ArithRef | None = None
        self._z3_lock = threading.Lock()

    @property
    def id(self) -> int:
        """Id."""
        """Property returning the id."""
        return self._id

    @property
    def name(self) -> str:
        """Name."""
        """Property returning the name."""
        return self._name

    def to_z3(self) -> z3.ArithRef:
        """Get Z3 representation for identity comparisons."""
        if self._z3_id is None:
            with self._z3_lock:
                if self._z3_id is None:
                    self._z3_id = z3.Int(f"id_{self._name}")
        return self._z3_id

    def __eq__(self, other: object) -> bool:
        """Eq."""
        """Check for equality with another object."""
        if isinstance(other, ObjectId):
            return self._id == other._id
        return False

    def __hash__(self) -> int:
        """Hash."""
        """Return the hash value of the object."""
        return hash(self._id)

    def __str__(self) -> str:
        """Str."""
        """Return a human-readable string representation."""
        return self._name

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"ObjectId({self._name})"


class AttributeState(Enum):
    """State of an object attribute."""

    CONCRETE = auto()
    SYMBOLIC = auto()
    DELETED = auto()
    UNKNOWN = auto()


@dataclass(slots=True)
class SymbolicAttribute:
    """A symbolic object attribute.

    Tracks the value, provenance, and lifecycle state of an attribute
    on a :class:`SymbolicObject` or :class:`SymbolicClass`.

    Attributes:
        name: Attribute name.
        value: Current attribute value (may be symbolic).
        state: Lifecycle state (:class:`AttributeState`).
        defined_in: Qualified class name where the attribute was defined.
        is_class_attr: ``True`` if this is a class-level attribute.
        is_method: ``True`` if the value is callable.
        is_property: ``True`` if the value is a property descriptor.
    """

    name: str
    value: Any
    state: AttributeState = AttributeState.CONCRETE
    defined_in: str | None = None
    is_class_attr: bool = False
    is_method: bool = False
    is_property: bool = False

    @classmethod
    def concrete(cls, name: str, value: object) -> SymbolicAttribute:
        """Create a concrete attribute."""
        return cls(name=name, value=value, state=AttributeState.CONCRETE)

    @classmethod
    def symbolic(cls, name: str, value: object) -> SymbolicAttribute:
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


@dataclass(slots=True)
class SymbolicClass:
    """Symbolic representation of a Python class/type.

    Tracks class name, base classes, attributes/methods, and caches
    the Method Resolution Order (C3 linearisation).

    Attributes:
        name: Short class name.
        qualname: Fully-qualified class name.
        bases: Tuple of direct base classes.
        metaclass: Optional metaclass.
        attributes: Mapping of attribute names to :class:`SymbolicAttribute`.
    """

    name: str
    qualname: str = ""
    bases: tuple[SymbolicClass, ...] = ()
    metaclass: SymbolicClass | None = None
    attributes: dict[str, SymbolicAttribute] = field(
        default_factory=lambda: dict[str, SymbolicAttribute]()
    )
    _mro: tuple[SymbolicClass, ...] | None = None
    _id: ObjectId | None = None
    _mro_lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self):
        """Post init."""
        if not self.qualname:
            self.qualname = self.name
        if self._id is None:
            self._id = ObjectId(f"class_{self.name}")

    @property
    def id(self) -> ObjectId:
        """Id."""
        """Property returning the id."""
        if self._id is None:
            self._id = ObjectId(f"class_{self.name}")
        return self._id

    @property
    def mro(self) -> tuple[SymbolicClass, ...]:
        """Compute or return cached Method Resolution Order."""
        if self._mro is None:
            with self._mro_lock:
                if self._mro is None:
                    self._mro = self._compute_mro()
        return self._mro

    def _compute_mro(self) -> tuple[SymbolicClass, ...]:
        """Compute MRO using C3 linearization."""
        return compute_mro(self)

    def get_attribute(self, name: str) -> SymbolicAttribute | None:
        """Get a class attribute."""
        return self.attributes.get(name)

    def set_attribute(self, name: str, value: object) -> None:
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
        """Str."""
        """Return a human-readable string representation."""
        return f"<class '{self.qualname}'>"

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"SymbolicClass({self.name !r})"


def compute_mro(cls: SymbolicClass) -> tuple[SymbolicClass, ...]:
    """Compute Method Resolution Order using C3 linearisation.

    Guarantees:

    1. Children precede parents.
    2. Parents maintain their declaration order.
    3. Consistent linearisation across the inheritance graph.

    Args:
        cls: The class to compute the MRO for.

    Returns:
        A tuple of :class:`SymbolicClass` in MRO order.

    Raises:
        TypeError: If a consistent MRO cannot be constructed.
    """
    if not cls.bases:
        return (cls,)

    def merge(seqs: list[list[SymbolicClass]]) -> list[SymbolicClass]:
        """Merge."""
        result: list[SymbolicClass] = []
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
    mro = merge([[cls]] + parent_mros + [parent_list])
    return tuple(mro)


@dataclass(slots=True)
class SymbolicObject:
    """Symbolic representation of a Python object instance.

    Tracks the class, instance attributes (``__dict__``), object identity,
    and optional ``__slots__`` values.

    Attributes:
        cls: The class that this object is an instance of.
        attributes: Instance attribute mapping.
        _id: Unique object identity.
        slots: Allowed slot names (``None`` if no ``__slots__``).
    """

    cls: SymbolicClass
    attributes: dict[str, SymbolicAttribute] = field(
        default_factory=lambda: dict[str, SymbolicAttribute]()
    )
    _id: ObjectId | None = None
    slots: tuple[str, ...] | None = None

    def __post_init__(self):
        """Post init."""
        if self._id is None:
            self._id = ObjectId(f"inst_{self.cls.name}")

    @property
    def id(self) -> ObjectId:
        """Id."""
        """Property returning the id."""
        if self._id is None:
            self._id = ObjectId(f"inst_{self.cls.name}")
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

    def set_attribute(self, name: str, value: object) -> None:
        """Set an instance attribute."""
        if self.slots is not None and name not in self.slots:
            msg = f"'{self.cls.name}' object has no attribute '{name}'"
            raise AttributeError(msg)
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
        """Str."""
        """Return a human-readable string representation."""
        return f"<{self.cls.qualname} object at {self._id}>"

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"SymbolicObject({self.cls.name !r}, {self._id})"


@dataclass(frozen=True, slots=True)
class SymbolicMethod:
    """Represents a bound or unbound method.

    Attributes:
        func: The underlying function/callable.
        instance: The bound instance (``None`` for unbound methods).
        owner: The class that owns this method.
    """

    func: Any
    instance: SymbolicObject | None = None
    owner: SymbolicClass | None = None

    @property
    def is_bound(self) -> bool:
        """Is bound."""
        """Property returning the is_bound."""
        return self.instance is not None

    @property
    def __self__(self) -> SymbolicObject | None:
        """Self."""
        """Property returning the __self__."""
        return self.instance

    @property
    def __func__(self) -> object:
        """Func."""
        """Property returning the __func__."""
        return self.func

    def bind(self, instance: SymbolicObject) -> SymbolicMethod:
        """Create a bound method."""
        return SymbolicMethod(
            func=self.func,
            instance=instance,
            owner=self.owner or instance.cls,
        )

    def __str__(self) -> str:
        """Str."""
        """Return a human-readable string representation."""
        if self.is_bound:
            return f"<bound method {self.func} of {self.instance}>"
        return f"<function {self.func}>"


@dataclass(frozen=True, slots=True)
class SymbolicProperty:
    """Symbolic property descriptor with optional getter, setter, and deleter.

    Attributes:
        fget: Getter callable (or ``None``).
        fset: Setter callable (or ``None``).
        fdel: Deleter callable (or ``None``).
        doc: Docstring for the property.
        name: Property name (for error messages).
    """

    fget: object | None = None
    fset: object | None = None
    fdel: object | None = None
    doc: str | None = None
    name: str = ""

    def __get__(
        self,
        obj: SymbolicObject | None,
        _objtype: SymbolicClass | None = None,
    ) -> object:
        """Get property value."""
        if obj is None:
            return self
        if self.fget is None:
            raise AttributeError(f"property '{self.name}' has no getter")
        return self.fget(obj)

    def __set__(self, obj: SymbolicObject, value: object) -> None:
        """Set property value."""
        if self.fset is None:
            raise AttributeError(f"property '{self.name}' has no setter")
        self.fset(obj, value)

    def __delete__(self, obj: SymbolicObject) -> None:
        """Delete property."""
        if self.fdel is None:
            raise AttributeError(f"property '{self.name}' has no deleter")
        self.fdel(obj)

    def getter(self, fget: object) -> SymbolicProperty:
        """Return property with new getter."""
        return SymbolicProperty(fget, self.fset, self.fdel, self.doc, self.name)

    def setter(self, fset: object) -> SymbolicProperty:
        """Return property with new setter."""
        return SymbolicProperty(self.fget, fset, self.fdel, self.doc, self.name)

    def deleter(self, fdel: object) -> SymbolicProperty:
        """Return property with new deleter."""
        return SymbolicProperty(self.fget, self.fset, fdel, self.doc, self.name)


@dataclass(frozen=True, slots=True)
class SymbolicSuper:
    """Proxy for ``super()`` that delegates attribute lookups through the MRO.

    Starts searching the MRO *after* ``type_``, matching Python's
    ``super()`` semantics.

    Attributes:
        type_: The class from which to start the MRO search.
        obj: The bound instance (``None`` for unbound super).
        obj_type: The type of ``obj`` (inferred if not given).
    """

    type_: SymbolicClass
    obj: SymbolicObject | None = None
    obj_type: SymbolicClass | None = None

    def __post_init__(self):
        """Post init."""
        if self.obj is not None and self.obj_type is None:
            object.__setattr__(self, "obj_type", self.obj.cls)

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
