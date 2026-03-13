"""
Enhanced OOP Support for PySyMex v1.2.
Provides improved class and object handling:
- Better __init__ parameter tracking
- Enhanced method dispatch with proper self binding
- Property and descriptor support
- Inheritance and MRO handling
- Dataclass support
- Slot handling
- Class method / static method support
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)

import z3

from pysymex.core.object_model import (
    OBJECT_CLASS,
    ObjectId,
    ObjectState,
    SymbolicAttribute,
    SymbolicClass,
    SymbolicMethod,
    SymbolicObject,
    SymbolicProperty,
)
from pysymex.core.types import SymbolicValue
from pysymex.core.types_containers import SymbolicDict, SymbolicList, SymbolicString


class MethodType(Enum):
    """Types of methods in a class."""

    INSTANCE = auto()
    CLASS = auto()
    STATIC = auto()
    PROPERTY = auto()
    ABSTRACT = auto()


@dataclass
class EnhancedMethod:
    """
    Enhanced method representation with type tracking.
    """

    func: Any
    method_type: MethodType = MethodType.INSTANCE
    name: str = ""
    qualname: str = ""
    owner: SymbolicClass | None = None
    bound_to: SymbolicObject | SymbolicClass | None = None
    parameters: list[str] = field(default_factory=list[str])
    defaults: dict[str, object] = field(default_factory=dict[str, object])
    annotations: dict[str, str] = field(default_factory=dict[str, str])

    @property
    def is_bound(self) -> bool:
        """Is bound."""
        """Property returning the is_bound."""
        return self.bound_to is not None

    def bind_to_instance(self, instance: SymbolicObject) -> EnhancedMethod:
        """Bind method to an instance."""
        if self.method_type == MethodType.STATIC:
            return self
        if self.method_type == MethodType.CLASS:
            return self.bind_to_class(instance.cls)
        return EnhancedMethod(
            func=self.func,
            method_type=self.method_type,
            name=self.name,
            qualname=self.qualname,
            owner=self.owner,
            bound_to=instance,
            parameters=self.parameters,
            defaults=self.defaults,
            annotations=self.annotations,
        )

    def bind_to_class(self, cls: SymbolicClass) -> EnhancedMethod:
        """Bind classmethod to a class."""
        return EnhancedMethod(
            func=self.func,
            method_type=self.method_type,
            name=self.name,
            qualname=self.qualname,
            owner=self.owner,
            bound_to=cls,
            parameters=self.parameters,
            defaults=self.defaults,
            annotations=self.annotations,
        )

    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        """
        Get the actual arguments for calling this method.
        Handles implicit self/cls insertion.
        """
        if self.method_type == MethodType.STATIC:
            return args, kwargs
        if self.method_type == MethodType.CLASS:
            if self.bound_to and isinstance(self.bound_to, SymbolicClass):
                return (self.bound_to,) + args, kwargs
            return args, kwargs
        if self.bound_to and isinstance(self.bound_to, SymbolicObject):
            return (self.bound_to,) + args, kwargs
        return args, kwargs


@dataclass
class InitParameter:
    """Parameter information for __init__."""

    name: str
    type_hint: str | None = None
    default: object = None
    has_default: bool = False
    is_self: bool = False

    def to_symbolic(self, pc: int) -> object:
        """Create a symbolic value for this parameter."""
        if self.is_self:
            return None
        type_map = {
            "int": lambda: SymbolicValue.symbolic(f"init_{self.name}_{pc}")[0],
            "str": lambda: SymbolicString.symbolic(f"init_{self.name}_{pc}")[0],
            "float": lambda: SymbolicValue.symbolic(f"init_{self.name}_{pc}")[0],
            "bool": lambda: SymbolicValue.symbolic_bool(f"init_{self.name}_{pc}")[0],
            "list": lambda: SymbolicList.symbolic(f"init_{self.name}_{pc}")[0],
            "dict": lambda: SymbolicDict.symbolic(f"init_{self.name}_{pc}")[0],
        }
        if self.type_hint in type_map:
            return type_map[self.type_hint]()
        if self.has_default:
            return self.default
        return SymbolicValue.symbolic(f"init_{self.name}_{pc}")[0]


@dataclass
class EnhancedClass:
    """
    Enhanced class representation with full OOP support.
    """

    base: SymbolicClass
    methods: dict[str, EnhancedMethod] = field(default_factory=dict[str, EnhancedMethod])
    class_methods: dict[str, EnhancedMethod] = field(default_factory=dict[str, EnhancedMethod])
    static_methods: dict[str, EnhancedMethod] = field(default_factory=dict[str, EnhancedMethod])
    properties: dict[str, SymbolicProperty] = field(default_factory=dict[str, SymbolicProperty])
    init_params: list[InitParameter] = field(default_factory=list[InitParameter])
    required_init_args: int = 0
    class_vars: dict[str, object] = field(default_factory=dict[str, object])
    slots: tuple[str, ...] | None = None
    is_dataclass: bool = False
    dataclass_fields: dict[str, Any] = field(default_factory=dict)
    abstract_methods: set[str] = field(default_factory=set[str])

    @property
    def name(self) -> str:
        """Name."""
        """Property returning the name."""
        return self.base.name

    @property
    def qualname(self) -> str:
        """Qualname."""
        """Property returning the qualname."""
        return self.base.qualname

    @property
    def is_abstract(self) -> bool:
        """Is abstract."""
        """Property returning the is_abstract."""
        return len(self.abstract_methods) > 0

    def add_method(
        self,
        name: str,
        func: object,
        method_type: MethodType = MethodType.INSTANCE,
        parameters: list[str] | None = None,
    ) -> None:
        """Add a method to the class."""
        method = EnhancedMethod(
            func=func,
            method_type=method_type,
            name=name,
            qualname=f"{self.qualname}.{name}",
            owner=self.base,
            parameters=parameters or [],
        )
        if method_type == MethodType.CLASS:
            self.class_methods[name] = method
        elif method_type == MethodType.STATIC:
            self.static_methods[name] = method
        elif method_type == MethodType.PROPERTY:
            self.properties[name] = SymbolicProperty(fget=func, name=name)
        else:
            self.methods[name] = method
        if method_type == MethodType.ABSTRACT:
            self.abstract_methods.add(name)
        self.base.set_attribute(name, method)

    def add_property(
        self,
        name: str,
        fget: object = None,
        fset: object = None,
        fdel: object = None,
    ) -> None:
        """Add a property to the class."""
        prop = SymbolicProperty(fget=fget, fset=fset, fdel=fdel, name=name)
        self.properties[name] = prop
        self.base.attributes[name] = SymbolicAttribute(
            name=name,
            value=prop,
            is_property=True,
        )

    def set_init_params(self, params: list[InitParameter]) -> None:
        """Set __init__ parameter info."""
        self.init_params = params
        self.required_init_args = sum(1 for p in params if not p.has_default and not p.is_self)

    def get_method(self, name: str) -> EnhancedMethod | None:
        """Get a method by name."""
        if name in self.methods:
            return self.methods[name]
        if name in self.class_methods:
            return self.class_methods[name]
        if name in self.static_methods:
            return self.static_methods[name]
        return None

    def lookup_method(self, name: str) -> EnhancedMethod | None:
        """Look up method through MRO."""
        method = self.get_method(name)
        if method:
            return method
        for parent in self.base.bases:
            attr = parent.get_attribute(name)
            if attr and attr.is_method:
                return attr.value
        return None


@dataclass
class EnhancedObject:
    """
    Enhanced object instance with proper attribute tracking.
    """

    base: SymbolicObject
    enhanced_class: EnhancedClass
    initialized: bool = False
    init_values: dict[str, object] = field(default_factory=dict[str, object])
    _modified_attrs: set[str] = field(default_factory=set[str])
    _accessed_attrs: set[str] = field(default_factory=set[str])

    @property
    def id(self) -> ObjectId:
        """Id."""
        """Property returning the id."""
        return self.base.id

    @property
    def cls(self) -> SymbolicClass:
        """Cls."""
        """Property returning the cls."""
        return self.base.cls

    def get_attribute(self, name: str) -> tuple[object, bool]:
        """
        Get attribute with full descriptor protocol.
        Returns (value, found).
        """
        self._accessed_attrs.add(name)
        if name in self.enhanced_class.properties:
            prop = self.enhanced_class.properties[name]
            if prop.fget is not None:
                result, _ = SymbolicValue.symbolic(f"prop_{name}_{self.id}")
                return result, True
        if self.base.has_attribute(name, check_class=False):
            attr = self.base.get_attribute(name, check_class=False)
            if attr is not None:
                return attr.value, True
        method = self.enhanced_class.get_method(name)
        if method:
            return method.bind_to_instance(self.base), True
        if name in self.enhanced_class.class_vars:
            return self.enhanced_class.class_vars[name], True
        attr = self.base.get_attribute(name, check_class=True)
        if attr and attr.is_present():
            value = attr.value
            if attr.is_method and isinstance(value, (SymbolicMethod, EnhancedMethod)):
                if isinstance(value, EnhancedMethod):
                    return value.bind_to_instance(self.base), True
                return value.bind(self.base), True
            return value, True
        return None, False

    def set_attribute(self, name: str, value: object) -> bool:
        """
        Set attribute with descriptor protocol.
        """
        self._modified_attrs.add(name)
        if name in self.enhanced_class.properties:
            prop = self.enhanced_class.properties[name]
            if prop.fset is not None:
                return True
            return False
        if self.enhanced_class.slots is not None:
            if name not in self.enhanced_class.slots:
                return False
        self.base.set_attribute(name, value)
        return True

    def call_method(
        self,
        name: str,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
    ) -> tuple[object, bool]:
        """
        Call a method on this object.
        Returns (result, found).
        """
        kwargs = kwargs or {}
        value, found = self.get_attribute(name)
        if not found:
            return None, False
        if isinstance(value, EnhancedMethod):
            _call_args, _call_kwargs = value.get_call_args(args, kwargs)
            return SymbolicValue.symbolic(f"call_{name}_{self.id}")[0], True
        if isinstance(value, SymbolicMethod):
            return SymbolicValue.symbolic(f"call_{name}_{self.id}")[0], True
        if callable(value):
            return SymbolicValue.symbolic(f"call_{name}_{self.id}")[0], True
        return None, False


class EnhancedClassRegistry:
    """
    Registry for enhanced class definitions.
    Tracks all class definitions encountered during analysis.
    """

    def __init__(self):
        """Init."""
        """Initialize the class instance."""
        self._classes: dict[str, EnhancedClass] = {}
        self._by_code: dict[int, EnhancedClass] = {}

    def register_class(
        self,
        name: str,
        bases: tuple[SymbolicClass, ...] = (),
        qualname: str = "",
    ) -> EnhancedClass:
        """Register a new class."""
        if not bases:
            bases = (OBJECT_CLASS,)
        base = SymbolicClass(
            name=name,
            qualname=qualname or name,
            bases=bases,
        )
        enhanced = EnhancedClass(base=base)
        self._classes[name] = enhanced
        return enhanced

    def get_class(self, name: str) -> EnhancedClass | None:
        """Get a class by name."""
        return self._classes.get(name)

    def register_by_code(
        self,
        code_id: int,
        enhanced: EnhancedClass,
    ) -> None:
        """Register class by code object ID."""
        self._by_code[code_id] = enhanced

    def get_by_code(self, code_id: int) -> EnhancedClass | None:
        """Get class by code object ID."""
        return self._by_code.get(code_id)

    def list_classes(self) -> list[str]:
        """List all registered class names."""
        return list(self._classes.keys())


def create_enhanced_instance(
    enhanced_class: EnhancedClass,
    object_state: ObjectState,
    args: tuple[object, ...] = (),
    kwargs: dict[str, object] | None = None,
    pc: int = 0,
) -> tuple[EnhancedObject, list[z3.ExprRef]]:
    """
    Create an instance with proper __init__ handling.
    Returns (instance, constraints).
    """
    kwargs = kwargs or {}
    constraints: list[z3.ExprRef] = []
    if enhanced_class.is_abstract:
        abstract_methods = "', '".join(sorted(enhanced_class.abstract_methods))
        raise TypeError(
            f"Can't instantiate abstract class {enhanced_class.name} without an implementation for abstract method '{abstract_methods}'"
        )
    base = object_state.create_object(enhanced_class.base)
    instance = EnhancedObject(
        base=base,
        enhanced_class=enhanced_class,
    )
    init_values: dict[str, object] = {}
    arg_idx = 0
    for param in enhanced_class.init_params:
        if param.is_self:
            continue
        if param.name in kwargs:
            init_values[param.name] = kwargs[param.name]
        elif arg_idx < len(args):
            init_values[param.name] = args[arg_idx]
            arg_idx += 1
        elif param.has_default:
            init_values[param.name] = param.default
        else:
            init_values[param.name] = param.to_symbolic(pc)
    for name, value in init_values.items():
        instance.set_attribute(name, value)
    instance.init_values = init_values
    instance.initialized = True
    return instance, constraints


def extract_init_params(code_obj: object) -> list[InitParameter]:
    """
    Extract __init__ parameters from a code object.
    """
    if not hasattr(code_obj, "co_varnames"):
        return []
    from typing import Any as _Any

    code_any: _Any = code_obj
    params: list[InitParameter] = []
    arg_count = getattr(code_any, "co_argcount", 0)
    varnames: tuple[str, ...] = code_any.co_varnames[:arg_count]
    defaults = getattr(code_any, "co_defaults", ()) or ()
    default_offset = arg_count - len(defaults)
    for i, name in enumerate(varnames):
        is_self = i == 0 and name in ("self", "cls")
        has_default = i >= default_offset
        default = defaults[i - default_offset] if has_default else None
        params.append(
            InitParameter(
                name=str(name),
                is_self=is_self,
                has_default=has_default,
                default=default,
            )
        )
    return params


def is_dataclass(cls: EnhancedClass) -> bool:
    """Check if class is a dataclass."""
    return cls.is_dataclass


def make_dataclass(
    cls: EnhancedClass,
    fields: dict[str, tuple[str, Any]],
) -> EnhancedClass:
    """
    Convert a class to a dataclass.
    Adds auto-generated __init__, __repr__, __eq__.
    """
    cls.is_dataclass = True
    cls.dataclass_fields = fields
    params = [InitParameter(name="self", is_self=True)]
    for name, (type_hint, default) in fields.items():
        params.append(
            InitParameter(
                name=name,
                type_hint=type_hint,
                default=default,
                has_default=default is not None,
            )
        )
    cls.set_init_params(params)
    return cls


@dataclass
class EnhancedSuper:
    """
    Enhanced super() implementation.
    """

    type_: EnhancedClass
    obj: EnhancedObject | None = None

    def get_method(self, name: str) -> EnhancedMethod | None:
        """Get method from parent class."""
        mro = self.type_.base.mro
        found_self = False
        for cls in mro:
            if found_self:
                attr = cls.get_attribute(name)
                if attr and attr.is_method:
                    method = attr.value
                    if isinstance(method, EnhancedMethod):
                        if self.obj:
                            return method.bind_to_instance(self.obj.base)
                        return method
            if cls == self.type_.base:
                found_self = True
        return None


enhanced_class_registry = EnhancedClassRegistry()


def get_enhanced_class(name: str) -> EnhancedClass | None:
    """Get an enhanced class by name."""
    return enhanced_class_registry.get_class(name)


def register_enhanced_class(
    name: str,
    bases: tuple[SymbolicClass, ...] = (),
) -> EnhancedClass:
    """Register a new enhanced class."""
    return enhanced_class_registry.register_class(name, bases)
