"""Object-oriented modeling for pysymex.
This module provides symbolic modeling of Python classes, instances,
methods, and inheritance for object-oriented code analysis.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)

import z3


class MethodType(Enum):
    """Types of class methods."""

    INSTANCE = auto()
    CLASS = auto()
    STATIC = auto()
    PROPERTY = auto()
    ABSTRACT = auto()
    MAGIC = auto()


@dataclass(frozen=True, slots=True)
class SymbolicAttribute:
    """A symbolic class/instance attribute."""

    name: str
    value: Any
    is_class_attr: bool = False
    is_readonly: bool = False
    type_hint: str | None = None

    def with_value(self, new_value: object) -> SymbolicAttribute:
        """Create copy with new value."""
        return SymbolicAttribute(
            name=self.name,
            value=new_value,
            is_class_attr=self.is_class_attr,
            is_readonly=self.is_readonly,
            type_hint=self.type_hint,
        )


@dataclass
class SymbolicMethod:
    """A symbolic method definition."""

    name: str
    func: Callable[..., object] | None = None
    method_type: MethodType = MethodType.INSTANCE
    parameters: list[str] = field(default_factory=list[str])
    return_type: str | None = None
    is_abstract: bool = False
    preconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    postconditions: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    modifies: set[str] = field(default_factory=set[str])


@dataclass
class SymbolicClass:
    """A symbolic class definition.
    Models Python classes for symbolic execution including:
    - Attributes (class and instance)
    - Methods (instance, class, static)
    - Inheritance (single and multiple)
    - Method Resolution Order (MRO)
    """

    name: str
    bases: list[SymbolicClass] = field(default_factory=lambda: [])
    class_attrs: dict[str, SymbolicAttribute] = field(default_factory=lambda: {})
    instance_attrs: dict[str, SymbolicAttribute] = field(default_factory=lambda: {})
    methods: dict[str, SymbolicMethod] = field(default_factory=lambda: {})
    is_abstract: bool = False
    metaclass: SymbolicClass | None = None
    module: str = "__main__"
    _mro: list[SymbolicClass] | None = None

    def __post_init__(self):
        """Post init."""
        self._compute_mro()

    def _compute_mro(self) -> None:
        """Compute Method Resolution Order using C3 linearization."""
        if not self.bases:
            self._mro = [self]
            return

        def merge(seqs: list[list[SymbolicClass]]) -> list[SymbolicClass]:
            """Merge."""
            result: list[SymbolicClass] = []
            while True:
                seqs = [s for s in seqs if s]
                if not seqs:
                    return result
                for seq in seqs:
                    candidate = seq[0]
                    in_tail = any(candidate in s[1:] for s in seqs)
                    if not in_tail:
                        result.append(candidate)
                        for s in seqs:
                            if s and s[0] == candidate:
                                s.pop(0)
                        break
                else:
                    raise TypeError("Cannot create MRO")
            return result

        base_mros = [list(base.mro) for base in self.bases]
        self._mro = [self] + merge(base_mros + [list(self.bases)])

    @property
    def mro(self) -> list[SymbolicClass]:
        """Get Method Resolution Order."""
        if self._mro is None:
            self._compute_mro()
        return self._mro or [self]

    def get_method(self, name: str) -> SymbolicMethod | None:
        """Get method by name, following MRO."""
        for cls in self.mro:
            if name in cls.methods:
                return cls.methods[name]
        return None

    def get_attribute(self, name: str) -> SymbolicAttribute | None:
        """Get class attribute by name, following MRO."""
        for cls in self.mro:
            if name in cls.class_attrs:
                return cls.class_attrs[name]
        return None

    def has_method(self, name: str) -> bool:
        """Check if class has a method (including inherited)."""
        return self.get_method(name) is not None

    def is_subclass_of(self, other: SymbolicClass) -> bool:
        """Check if this class is a subclass of other."""
        return other in self.mro

    def add_method(
        self,
        name: str,
        func: Callable[..., object] | None = None,
        method_type: MethodType = MethodType.INSTANCE,
        **kwargs: object,
    ) -> None:
        """Add a method to the class."""
        self.methods[name] = SymbolicMethod(
            name=name,
            func=func,
            method_type=method_type,
            **kwargs,
        )

    def add_class_attr(
        self,
        name: str,
        value: object,
        **kwargs: object,
    ) -> None:
        """Add a class attribute."""
        self.class_attrs[name] = SymbolicAttribute(
            name=name,
            value=value,
            is_class_attr=True,
            **kwargs,
        )


@dataclass
class SymbolicInstance:
    """A symbolic instance of a class.
    Represents an object with symbolic attribute values.
    """

    cls: SymbolicClass
    instance_id: int
    attrs: dict[str, object] = field(default_factory=lambda: {})
    _z3_id: z3.ArithRef | None = None

    @property
    def z3_id(self) -> z3.ArithRef:
        """Get Z3 integer representing object identity."""
        if self._z3_id is None:
            self._z3_id = z3.Int(f"obj_{self .instance_id }")
        return self._z3_id

    def get_attr(self, name: str) -> object:
        """Get an attribute value.
        Checks instance attrs first, then class attrs via MRO.
        """
        if name in self.attrs:
            return self.attrs[name]
        class_attr = self.cls.get_attribute(name)
        if class_attr is not None:
            return class_attr.value
        method = self.cls.get_method(name)
        if method is not None:
            return BoundMethod(instance=self, method=method)
        return None

    def set_attr(self, name: str, value: object) -> None:
        """Set an instance attribute."""
        self.attrs[name] = value

    def has_attr(self, name: str) -> bool:
        """Check if attribute exists."""
        return (
            name in self.attrs
            or self.cls.get_attribute(name) is not None
            or self.cls.get_method(name) is not None
        )

    def del_attr(self, name: str) -> bool:
        """Delete an instance attribute."""
        if name in self.attrs:
            del self.attrs[name]
            return True
        return False

    def isinstance_of(self, cls: SymbolicClass) -> bool:
        """Check if instance is of a class (including subclasses)."""
        return self.cls.is_subclass_of(cls)


@dataclass
class BoundMethod:
    """A method bound to an instance."""

    instance: SymbolicInstance
    method: SymbolicMethod

    def __call__(self, *args: object, **kwargs: object) -> object:
        """Call the bound method."""
        if self.method.func is not None:
            return self.method.func(self.instance, *args, **kwargs)
        return None


class ClassRegistry:
    """Registry of symbolic class definitions.
    Tracks all classes seen during analysis for type hierarchy
    and instanceof checks.
    """

    def __init__(self):
        """Initialize a new ClassRegistry instance."""
        self._classes: dict[str, SymbolicClass] = {}
        self._builtin_classes: dict[str, SymbolicClass] = {}
        self._next_instance_id: int = 0
        self._init_builtins()

    def _init_builtins(self) -> None:
        """Initialize symbolic versions of builtin classes."""
        obj_cls = SymbolicClass(name="object", module="builtins")
        obj_cls.add_method("__init__")
        obj_cls.add_method("__str__")
        obj_cls.add_method("__repr__")
        obj_cls.add_method("__eq__")
        obj_cls.add_method("__hash__")
        self._builtin_classes["object"] = obj_cls
        type_cls = SymbolicClass(name="type", bases=[obj_cls], module="builtins")
        self._builtin_classes["type"] = type_cls
        exc_cls = SymbolicClass(name="Exception", bases=[obj_cls], module="builtins")
        self._builtin_classes["Exception"] = exc_cls
        for name in ["int", "str", "float", "bool", "list", "dict", "set", "tuple"]:
            cls = SymbolicClass(name=name, bases=[obj_cls], module="builtins")
            self._builtin_classes[name] = cls

    def register_class(self, cls: SymbolicClass) -> None:
        """Register a class definition."""
        full_name = f"{cls .module }.{cls .name }"
        self._classes[full_name] = cls

    def get_class(self, name: str, module: str = "__main__") -> SymbolicClass | None:
        """Get a class by name."""
        full_name = f"{module }.{name }"
        if full_name in self._classes:
            return self._classes[full_name]
        if name in self._builtin_classes:
            return self._builtin_classes[name]
        return None

    def create_instance(
        self,
        cls: SymbolicClass,
        init_attrs: dict[str, object] | None = None,
    ) -> SymbolicInstance:
        """Create a new instance of a class."""
        instance_id = self._next_instance_id
        self._next_instance_id += 1
        instance = SymbolicInstance(
            cls=cls,
            instance_id=instance_id,
            attrs=init_attrs or {},
        )
        return instance

    def get_builtin(self, name: str) -> SymbolicClass | None:
        """Get a builtin class."""
        return self._builtin_classes.get(name)


class TypeChecker:
    """Runtime type checking for symbolic execution."""

    def __init__(self, registry: ClassRegistry):
        """Initialize a new TypeChecker instance."""
        self.registry = registry

    def isinstance_check(
        self,
        value: object,
        target_cls: SymbolicClass,
    ) -> z3.BoolRef:
        """Generate symbolic isinstance check."""
        if isinstance(value, SymbolicInstance):
            return z3.BoolVal(value.isinstance_of(target_cls))
        type_name = type(value).__name__
        builtin = self.registry.get_builtin(type_name)
        if builtin:
            return z3.BoolVal(builtin.is_subclass_of(target_cls))
        return z3.BoolVal(False)

    def issubclass_check(
        self,
        child: SymbolicClass,
        parent: SymbolicClass,
    ) -> z3.BoolRef:
        """Generate symbolic issubclass check."""
        return z3.BoolVal(child.is_subclass_of(parent))

    def type_of(self, value: object) -> SymbolicClass | None:
        """Get the symbolic class of a value."""
        if isinstance(value, SymbolicInstance):
            return value.cls
        type_name = type(value).__name__
        return self.registry.get_builtin(type_name)


class SymbolicDescriptor:
    """Base class for symbolic descriptors (property, classmethod, etc.)."""

    def __get__(self, instance: SymbolicInstance | None, owner: SymbolicClass) -> object:
        """Get."""
        raise NotImplementedError

    def __set__(self, instance: SymbolicInstance, value: object) -> None:
        """Set."""
        raise NotImplementedError

    def __delete__(self, instance: SymbolicInstance) -> None:
        """Delete."""
        raise NotImplementedError


class SymbolicProperty(SymbolicDescriptor):
    """Symbolic property descriptor."""

    def __init__(
        self,
        fget: Callable[..., object] | None = None,
        fset: Callable[..., object] | None = None,
        fdel: Callable[..., object] | None = None,
        doc: str | None = None,
    ):
        """Initialize a new SymbolicProperty instance."""
        self.fget: Callable[..., object] | None = fget
        self.fset: Callable[..., object] | None = fset
        self.fdel: Callable[..., object] | None = fdel
        self.__doc__ = doc

    def __get__(self, instance: SymbolicInstance | None, owner: SymbolicClass) -> object:
        """Get."""
        if instance is None:
            return self
        if self.fget is None:
            raise AttributeError("unreadable attribute")
        return self.fget(instance)

    def __set__(self, instance: SymbolicInstance, value: object) -> None:
        """Set."""
        if self.fset is None:
            raise AttributeError("can't set attribute")
        self.fset(instance, value)

    def __delete__(self, instance: SymbolicInstance) -> None:
        """Delete."""
        if self.fdel is None:
            raise AttributeError("can't delete attribute")
        self.fdel(instance)


__all__ = [
    "BoundMethod",
    "ClassRegistry",
    "MethodType",
    "SymbolicAttribute",
    "SymbolicClass",
    "SymbolicDescriptor",
    "SymbolicInstance",
    "SymbolicMethod",
    "SymbolicProperty",
    "TypeChecker",
]
