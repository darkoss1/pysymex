"""Extended builtin function models.

Contains models for less-commonly-used Python builtins:
iter, next, super, issubclass, globals, locals, dict, set, reversed,
all, any, ord, chr, pow, round, divmod, hasattr, getattr, setattr,
id, hash, callable, repr, format, input, open.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import z3

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState

from pysymex.core.types import (
    SymbolicNone,
    SymbolicValue,
)
from pysymex.core.types_containers import (
    SymbolicDict,
    SymbolicList,
    SymbolicString,
)

from .builtins_base import FunctionModel, ModelResult


class IterModel(FunctionModel):
    """Model for iter()."""

    name = "iter"
    qualname = "builtins.iter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, (list, tuple, str, SymbolicList, SymbolicString)):
            return ModelResult(value=val)
        result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NextModel(FunctionModel):
    """Model for next()."""

    name = "next"
    qualname = "builtins.next"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SuperModel(FunctionModel):
    """Model for super()."""

    name = "super"
    qualname = "builtins.super"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"super_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IssubclassModel(FunctionModel):
    """Model for issubclass()."""

    name = "issubclass"
    qualname = "builtins.issubclass"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"issubclass_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GlobalsModel(FunctionModel):
    """Model for globals()."""

    name = "globals"
    qualname = "builtins.globals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"globals_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class LocalsModel(FunctionModel):
    """Model for locals()."""

    name = "locals"
    qualname = "builtins.locals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"locals_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DictModel(FunctionModel):
    """Model for dict()."""

    name = "dict"
    qualname = "builtins.dict"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args and not kwargs:
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if kwargs and not args:
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetModel(FunctionModel):
    """Model for set()."""

    name = "set"
    qualname = "builtins.set"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_int == 0])
        val = args[0]
        if isinstance(val, (list, tuple, set)):
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_int
                    == len(set(cast("list[object] | tuple[object, ...] | set[object]", val))),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReversedModel(FunctionModel):
    """Model for reversed()."""

    name = "reversed"
    qualname = "builtins.reversed"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, SymbolicList):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_len == val.z3_len])
        if isinstance(val, (list, tuple, str)):
            return ModelResult(
                value=list(reversed(cast("list[object] | tuple[object, ...] | str", val)))
            )
        result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AllModel(FunctionModel):
    """Model for all()."""

    name = "all"
    qualname = "builtins.all"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(True))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(True))
            val_seq = cast("list[object] | tuple[object, ...]", val)
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [cast("Any", x).is_truthy() for x in sv_list]
                result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.And(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(all(val_seq)))
        result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class AnyModel(FunctionModel):
    """Model for any()."""

    name = "any"
    qualname = "builtins.any"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(False))
            val_seq = cast("list[object] | tuple[object, ...]", val)
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [cast("Any", x).is_truthy() for x in sv_list]
                result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.Or(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(any(val_seq)))
        result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OrdModel(FunctionModel):
    """Model for ord()."""

    name = "ord"
    qualname = "builtins.ord"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        val = args[0]
        if isinstance(val, str) and len(val) == 1:
            return ModelResult(value=SymbolicValue.from_const(ord(val)))
        if isinstance(val, SymbolicString):
            result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int >= 0,
                    result.z3_int < 0x110000,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class ChrModel(FunctionModel):
    """Model for chr()."""

    name = "chr"
    qualname = "builtins.chr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, int) and 0 <= val < 0x110000:
            return ModelResult(value=SymbolicString.from_const(chr(val)))
        if isinstance(val, SymbolicValue):
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    val.z3_int >= 0,
                    val.z3_int < 0x110000,
                    result.z3_len == 1,
                ],
            )
        result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len == 1])


class PowModel(FunctionModel):
    """Model for pow()."""

    name = "pow"
    qualname = "builtins.pow"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        base, exp = args[0], args[1]
        mod = args[2] if len(args) > 2 else None
        if isinstance(base, (int, float)) and isinstance(exp, (int, float)):
            if mod is not None and isinstance(mod, int):
                return ModelResult(value=SymbolicValue.from_const(pow(base, exp, mod)))
            return ModelResult(value=SymbolicValue.from_const(pow(base, exp)))
        result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RoundModel(FunctionModel):
    """Model for round()."""

    name = "round"
    qualname = "builtins.round"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        ndigits = args[1] if len(args) > 1 else None
        if isinstance(val, (int, float)):
            result = round(val, ndigits)
            return ModelResult(value=result)
        result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DivmodModel(FunctionModel):
    """Model for divmod()."""

    name = "divmod"
    qualname = "builtins.divmod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            return ModelResult(value=(SymbolicValue.from_const(0), SymbolicValue.from_const(0)))
        a, b = args[0], args[1]
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            q, r = divmod(a, b)
            return ModelResult(value=(SymbolicValue.from_const(q), SymbolicValue.from_const(r)))
        if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
            quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
            remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
            return ModelResult(
                value=(quotient, remainder),
                constraints=[
                    c1,
                    c2,
                    quotient.is_int,
                    remainder.is_int,
                    a.z3_int == b.z3_int * quotient.z3_int + remainder.z3_int,
                    z3.If(
                        b.z3_int > 0,
                        z3.And(remainder.z3_int >= 0, remainder.z3_int < b.z3_int),
                        z3.And(remainder.z3_int <= 0, remainder.z3_int > b.z3_int),
                    ),
                    b.z3_int != 0,
                ],
            )
        quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
        remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
        return ModelResult(value=(quotient, remainder), constraints=[c1, c2])


class HasattrModel(FunctionModel):
    """Model for hasattr()."""

    name = "hasattr"
    qualname = "builtins.hasattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"hasattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        obj, name = args[0], args[1]
        if not isinstance(obj, SymbolicValue) and isinstance(name, str):
            return ModelResult(value=SymbolicValue.from_const(hasattr(obj, name)))
        result, constraint = SymbolicValue.symbolic(f"hasattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GetattrModel(FunctionModel):
    """Model for getattr()."""

    name = "getattr"
    qualname = "builtins.getattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        obj, name = args[0], args[1]
        default = args[2] if len(args) > 2 else None
        if not isinstance(obj, SymbolicValue) and isinstance(name, str):
            try:
                return ModelResult(value=getattr(obj, name))
            except AttributeError:
                if default is not None:
                    return ModelResult(value=default)
        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetattrModel(FunctionModel):
    """Model for setattr()."""

    name = "setattr"
    qualname = "builtins.setattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone("none"), side_effects={"mutates_arg": 0})


class IdModel(FunctionModel):
    """Model for id()."""

    name = "id"
    qualname = "builtins.id"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            result, constraint = SymbolicValue.symbolic(f"id_{state.pc}")
            return ModelResult(
                value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
            )
        result, constraint = SymbolicValue.symbolic(f"id_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class HashModel(FunctionModel):
    """Model for hash()."""

    name = "hash"
    qualname = "builtins.hash"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            if isinstance(obj, (int, str, float, tuple, frozenset, type(None))):
                return ModelResult(
                    value=SymbolicValue.from_const(
                        hash(
                            cast(
                                "int | str | float | tuple[object, ...] | frozenset[object] | None",
                                obj,
                            )
                        )
                    )
                )
        result, constraint = SymbolicValue.symbolic(f"hash_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class CallableModel(FunctionModel):
    """Model for callable()."""

    name = "callable"
    qualname = "builtins.callable"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            if not isinstance(obj, SymbolicValue):
                return ModelResult(value=SymbolicValue.from_const(callable(obj)))
        result, constraint = SymbolicValue.symbolic(f"callable_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class ReprModel(FunctionModel):
    """Model for repr()."""

    name = "repr"
    qualname = "builtins.repr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            if not isinstance(obj, SymbolicValue):
                return ModelResult(value=SymbolicString.from_const(repr(obj)))
        result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FormatModel(FunctionModel):
    """Model for format()."""

    name = "format"
    qualname = "builtins.format"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            spec = args[1] if len(args) > 1 else ""
            if not isinstance(obj, SymbolicValue) and isinstance(spec, str):
                return ModelResult(value=SymbolicString.from_const(format(obj, spec)))
        result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class InputModel(FunctionModel):
    """Model for input()."""

    name = "input"
    qualname = "builtins.input"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"input_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class OpenModel(FunctionModel):
    """Model for open()."""

    name = "open"
    qualname = "builtins.open"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"file_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class ExecModel(FunctionModel):
    """Model for exec() - code injection taint sink."""

    name = "exec"
    qualname = "builtins.exec"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        side_effects: dict[str, object] = {
            "code_injection": True,
            "sink_type": "exec",
        }
        if args:
            code_arg = args[0]
            if isinstance(code_arg, (SymbolicString, SymbolicValue)):
                side_effects["tainted_input"] = True
                side_effects["severity"] = "critical"
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class EvalModel(FunctionModel):
    """Model for eval() - code injection taint sink."""

    name = "eval"
    qualname = "builtins.eval"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        side_effects: dict[str, object] = {
            "code_injection": True,
            "sink_type": "eval",
        }
        if args:
            code_arg = args[0]
            if isinstance(code_arg, (SymbolicString, SymbolicValue)):
                side_effects["tainted_input"] = True
                side_effects["severity"] = "critical"
        result, constraint = SymbolicValue.symbolic(f"eval_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=side_effects,
        )


class CompileModel(FunctionModel):
    """Model for compile()."""

    name = "compile"
    qualname = "builtins.compile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        side_effects: dict[str, object] = {"code_injection": True, "sink_type": "compile"}
        if args and isinstance(args[0], (SymbolicString, SymbolicValue)):
            side_effects["tainted_input"] = True
            side_effects["severity"] = "critical"
        result, constraint = SymbolicValue.symbolic(f"code_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects=side_effects)


class BinModel(FunctionModel):
    """Model for bin()."""

    name = "bin"
    qualname = "builtins.bin"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"bin_{state.pc}")
        constraints = [constraint]
        if args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class OctModel(FunctionModel):
    """Model for oct()."""

    name = "oct"
    qualname = "builtins.oct"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"oct_{state.pc}")
        constraints = [constraint]
        if args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class HexModel(FunctionModel):
    """Model for hex()."""

    name = "hex"
    qualname = "builtins.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
        constraints = [constraint]
        if args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class BytesModel(FunctionModel):
    """Model for bytes() constructor."""

    name = "bytes"
    qualname = "builtins.bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_{state.pc}")
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        elif args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


class BytearrayModel(FunctionModel):
    """Model for bytearray() constructor."""

    name = "bytearray"
    qualname = "builtins.bytearray"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytearray_{state.pc}")
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        elif args:
            val = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


class FrozensetModel(FunctionModel):
    """Model for frozenset() constructor."""

    name = "frozenset"
    qualname = "builtins.frozenset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"frozenset_{state.pc}")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        return ModelResult(value=result, constraints=constraints)


class MemoryviewModel(FunctionModel):
    """Model for memoryview()."""

    name = "memoryview"
    qualname = "builtins.memoryview"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"memoryview_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ObjectModel(FunctionModel):
    """Model for object()."""

    name = "object"
    qualname = "builtins.object"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"object_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PropertyModel(FunctionModel):
    """Model for property()."""

    name = "property"
    qualname = "builtins.property"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"property_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ClassmethodModel(FunctionModel):
    """Model for classmethod()."""

    name = "classmethod"
    qualname = "builtins.classmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=args[0] if args else SymbolicNone())


class StaticmethodModel(FunctionModel):
    """Model for staticmethod()."""

    name = "staticmethod"
    qualname = "builtins.staticmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=args[0] if args else SymbolicNone())


class VarsModel(FunctionModel):
    """Model for vars()."""

    name = "vars"
    qualname = "builtins.vars"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"vars_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DirModel(FunctionModel):
    """Model for dir()."""

    name = "dir"
    qualname = "builtins.dir"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dir_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AsciiModel(FunctionModel):
    """Model for ascii()."""

    name = "ascii"
    qualname = "builtins.ascii"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"ascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class BreakpointModel(FunctionModel):
    """Model for breakpoint()."""

    name = "breakpoint"
    qualname = "builtins.breakpoint"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone())


class __import__Model(FunctionModel):
    """Model for __import__()."""

    name = "__import__"
    qualname = "builtins.__import__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"import_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewTobytesModel(FunctionModel):
    name = "tobytes"
    qualname = "memoryview.tobytes"

    def apply(self, args, kwargs, state):
        result, constraint = SymbolicValue.symbolic(f"tobytes_{state.pc}", bytes)
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewTolistModel(FunctionModel):
    name = "tolist"
    qualname = "memoryview.tolist"

    def apply(self, args, kwargs, state):
        from pysymex.core.types import SymbolicList

        return ModelResult(value=SymbolicList([]), constraints=[])


class MemoryviewHexModel(FunctionModel):
    name = "hex"
    qualname = "memoryview.hex"

    def apply(self, args, kwargs, state):
        result, constraint = SymbolicValue.symbolic(f"hex_{state.pc}", str)
        return ModelResult(value=result, constraints=[constraint, result.is_string])


class MemoryviewReleaseModel(FunctionModel):
    name = "release"
    qualname = "memoryview.release"

    def apply(self, args, kwargs, state):
        return ModelResult(value=None, constraints=[])


class MemoryviewCastModel(FunctionModel):
    name = "cast"
    qualname = "memoryview.cast"

    def apply(self, args, kwargs, state):
        if not args:
            return ModelResult(value=None, constraints=[])
        return ModelResult(value=args[0], constraints=[])


class ComplexRealModel(FunctionModel):
    name = "real"
    qualname = "complex.real"

    def apply(self, args, kwargs, state):
        if not args:
            return ModelResult(0.0, [], {})
        return ModelResult(args[0], [], {})


class ComplexImagModel(FunctionModel):
    name = "imag"
    qualname = "complex.imag"

    def apply(self, args, kwargs, state):
        return ModelResult(0.0, [], {})


class ComplexConjugateModel(FunctionModel):
    name = "conjugate"
    qualname = "complex.conjugate"

    def apply(self, args, kwargs, state):
        if not args:
            return ModelResult(0.0, [], {})
        return ModelResult(args[0], [], {})


EXTENDED_MODELS = [
    AllModel(),
    AnyModel(),
    AsciiModel(),
    BreakpointModel(),
    BinModel(),
    BytearrayModel(),
    BytesModel(),
    CallableModel(),
    ChrModel(),
    ClassmethodModel(),
    CompileModel(),
    DictModel(),
    DirModel(),
    DivmodModel(),
    EvalModel(),
    ExecModel(),
    FormatModel(),
    FrozensetModel(),
    GetattrModel(),
    GlobalsModel(),
    HasattrModel(),
    HashModel(),
    HexModel(),
    IdModel(),
    InputModel(),
    IssubclassModel(),
    IterModel(),
    LocalsModel(),
    MemoryviewModel(),
    NextModel(),
    ObjectModel(),
    OctModel(),
    OpenModel(),
    OrdModel(),
    PowModel(),
    PropertyModel(),
    ReprModel(),
    ReversedModel(),
    RoundModel(),
    SetattrModel(),
    SetModel(),
    StaticmethodModel(),
    SuperModel(),
    VarsModel(),
    __import__Model(),
    MemoryviewTobytesModel(),
    MemoryviewTolistModel(),
    MemoryviewHexModel(),
    MemoryviewReleaseModel(),
    MemoryviewCastModel(),
    ComplexRealModel(),
    ComplexImagModel(),
    ComplexConjugateModel(),
]
