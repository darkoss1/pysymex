"""Extended symbolic type system public exports."""

from __future__ import annotations

from typing import cast

import z3

from .base import (
	SYMBOLIC_NONE,
	SymbolicNoneType,
	SymbolicType,
	TypeTag,
	fresh_name,
	reset_counters,
)
from .symbolic_containers import (
	SymbolicBytes,
	SymbolicDict,
	SymbolicList,
	SymbolicSet,
	SymbolicString,
	SymbolicTuple,
)
from .numeric import (
	SymbolicBool,
	SymbolicFloat,
	SymbolicInt,
)


def coerce_to_bool(value: SymbolicType) -> SymbolicBool:
	"""Convert any symbolic type to boolean."""
	if isinstance(value, SymbolicBool):
		return value
	return SymbolicBool(value.is_truthy())


def coerce_to_int(value: SymbolicType) -> SymbolicInt:
	"""Convert symbolic type to int where possible."""
	match value:
		case SymbolicInt():
			return value
		case SymbolicBool():
			return SymbolicInt(z3.If(value.z3_bool, z3.IntVal(1), z3.IntVal(0)))
		case SymbolicFloat():
			return value.to_int()
		case _:
			return SymbolicInt.symbolic(f"int_{value.name}")


def coerce_to_float(value: SymbolicType) -> SymbolicFloat:
	"""Convert symbolic type to float where possible."""
	match value:
		case SymbolicFloat():
			return value
		case SymbolicInt():
			return SymbolicFloat(z3.ToReal(value.z3_int))
		case SymbolicBool():
			return SymbolicFloat(z3.If(value.z3_bool, z3.RealVal(1), z3.RealVal(0)))
		case _:
			return SymbolicFloat.symbolic(f"float_{value.name}")


def coerce_to_string(value: SymbolicType) -> SymbolicString:
	"""Convert symbolic type to string where possible."""
	if isinstance(value, SymbolicString):
		return value
	elif isinstance(value, SymbolicInt):
		return SymbolicString(z3.IntToStr(value.z3_int))
	else:
		return SymbolicString.symbolic(f"str_{value.name}")


def symbolic_from_python(value: object) -> SymbolicType:
	"""Create a symbolic value from a Python value."""
	match value:
		case None:
			return SYMBOLIC_NONE
		case bool() as v:
			return SymbolicBool.concrete(v)
		case int() as v:
			return SymbolicInt.concrete(v)
		case float() as v:
			return SymbolicFloat.concrete(v)
		case str() as v:
			return SymbolicString.concrete(v)
		case bytes() as v:
			return SymbolicBytes.concrete(v)
		case tuple() as v:
			elements = tuple(symbolic_from_python(e) for e in cast("tuple[object, ...]", v))
			return SymbolicTuple(elements)
		case list() as v:
			_lv = cast("list[object]", v)
			if not _lv:
				return SymbolicList.concrete_int_list([])
			if all(isinstance(e, int) for e in _lv):
				return SymbolicList.concrete_int_list(cast("list[int]", _lv))
			return SymbolicList.symbolic_int_list()
		case dict():
			return SymbolicDict.symbolic_int_dict()
		case set():
			return SymbolicSet.symbolic_int_set()
		case _:
			return SymbolicInt.symbolic(f"unknown_{type(value).__name__}")


def symbolic_for_type(type_hint: type, name: str | None = None) -> SymbolicType:
	"""Create a fresh symbolic value for a type hint."""
	match type_hint:
		case t if t is type(None):
			return SYMBOLIC_NONE
		case t if t is bool:
			return SymbolicBool.symbolic(name)
		case t if t is int:
			return SymbolicInt.symbolic(name)
		case t if t is float:
			return SymbolicFloat.symbolic(name)
		case t if t is str:
			return SymbolicString.symbolic(name)
		case t if t is bytes:
			return SymbolicBytes.symbolic(name)
		case t if t is list:
			return SymbolicList.symbolic_int_list(name)
		case t if t is dict:
			return SymbolicDict.symbolic_int_dict(name)
		case t if t is set:
			return SymbolicSet.symbolic_int_set(name)
		case _:
			return SymbolicInt.symbolic(name)


def is_numeric(value: SymbolicType) -> bool:
	"""Check if value is numeric (int or float)."""
	return isinstance(value, (SymbolicInt, SymbolicFloat))


def is_sequence(value: SymbolicType) -> bool:
	"""Check if value is a sequence type."""
	return isinstance(value, (SymbolicString, SymbolicBytes, SymbolicTuple, SymbolicList))


def is_collection(value: SymbolicType) -> bool:
	"""Check if value is any collection type."""
	return isinstance(value, (SymbolicTuple, SymbolicList, SymbolicDict, SymbolicSet))


def get_common_type(a: SymbolicType, b: SymbolicType) -> TypeTag:
	"""Get the common type for binary operations."""
	if isinstance(a, SymbolicFloat) or isinstance(b, SymbolicFloat):
		return TypeTag.FLOAT
	if isinstance(a, SymbolicInt) or isinstance(b, SymbolicInt):
		return TypeTag.INT
	if isinstance(a, SymbolicBool) and isinstance(b, SymbolicBool):
		return TypeTag.BOOL
	return TypeTag.UNKNOWN


__all__ = [
	"SYMBOLIC_NONE",
	"SymbolicBool",
	"SymbolicBytes",
	"SymbolicDict",
	"SymbolicFloat",
	"SymbolicInt",
	"SymbolicList",
	"SymbolicNoneType",
	"SymbolicSet",
	"SymbolicString",
	"SymbolicTuple",
	"SymbolicType",
	"TypeTag",
	"coerce_to_bool",
	"coerce_to_float",
	"coerce_to_int",
	"coerce_to_string",
	"fresh_name",
	"get_common_type",
	"is_collection",
	"is_numeric",
	"is_sequence",
	"reset_counters",
	"symbolic_for_type",
	"symbolic_from_python",
]
