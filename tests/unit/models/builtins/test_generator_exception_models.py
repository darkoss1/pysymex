from __future__ import annotations

import types
from collections.abc import Callable
from typing import cast

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.payload import SymbolicFunctionPayload
from pysymex.execution.opcodes.common.generators import ModeledGenerator
from pysymex.models.builtins import AnyModel
from pysymex.models.builtins.results import is_potential_exception_effect
from pysymex.typing import StackValue


def _gate(value: int, flag: int) -> bool:
    if flag == 1 and value == 0:
        raise LookupError("masked zero")
    return value == 0


def _wrap(value: int, flag: int, salt: int) -> bool:
    return _gate(value, flag) or salt == 7


def _direct_template(values: list[int], flag: int) -> object:
    return (_gate(item, flag) for item in values)


def _nested_template(values: list[int], salt: int, flag: int) -> object:
    return (_wrap(item, flag, salt) for item in values)


def _genexpr_code(template: Callable[..., object]) -> types.CodeType:
    for constant in template.__code__.co_consts:
        if isinstance(constant, types.CodeType):
            return constant
    raise AssertionError("missing generator expression code")


def _modeled_generator(
    code: types.CodeType,
    item: SymbolicValue,
    closure_by_name: dict[str, object],
) -> ModeledGenerator:
    source = SymbolicList(
        "generator_source",
        z3.Array("generator_source_items", z3.IntSort(), z3.IntSort()),
        z3.IntVal(1),
        _concrete_items=[item],
    )
    closure = tuple(closure_by_name[name] for name in code.co_freevars)
    iterator = SymbolicIterator("generator_iterator", source)
    return ModeledGenerator(
        "<genexpr>",
        SymbolicFunctionPayload(code=code, closure=closure),
        (iterator,),
        (),
    )


def _assert_lookup_error_condition(
    *,
    condition: z3.BoolRef,
    item: SymbolicValue,
    item_constraint: z3.BoolRef,
    flag: SymbolicValue,
    flag_constraint: z3.BoolRef,
) -> None:
    solver = z3.Solver()
    solver.add(item_constraint, flag_constraint, condition, item.z3_int == 0, flag.z3_int == 1)
    assert solver.check() == z3.sat

    solver = z3.Solver()
    solver.add(item_constraint, flag_constraint, condition, item.z3_int != 0)
    assert solver.check() == z3.unsat

    solver = z3.Solver()
    solver.add(item_constraint, flag_constraint, condition, flag.z3_int != 1)
    assert solver.check() == z3.unsat


def test_any_modeled_generator_routes_builtin_exception_predicate() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    flag, flag_constraint = SymbolicValue.symbolic_int("flag")
    code = _genexpr_code(_direct_template)
    generator = _modeled_generator(code, item, {"flag": flag})
    state = VMState(pc=0, global_vars={"_gate": _gate})

    result = AnyModel().apply([cast(StackValue, generator)], {}, state)

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "LookupError"
    assert effect["message"] == "masked zero"
    _assert_lookup_error_condition(
        condition=effect["condition"],
        item=item,
        item_constraint=item_constraint,
        flag=flag,
        flag_constraint=flag_constraint,
    )


def test_any_modeled_generator_routes_nested_predicate_exception() -> None:
    item, item_constraint = SymbolicValue.symbolic_int("item")
    flag, flag_constraint = SymbolicValue.symbolic_int("flag")
    salt, _salt_constraint = SymbolicValue.symbolic_int("salt")
    code = _genexpr_code(_nested_template)
    generator = _modeled_generator(code, item, {"flag": flag, "salt": salt})
    state = VMState(pc=0, global_vars={"_wrap": _wrap})

    result = AnyModel().apply([cast(StackValue, generator)], {}, state)

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "LookupError"
    assert effect["message"] == "masked zero"
    _assert_lookup_error_condition(
        condition=effect["condition"],
        item=item,
        item_constraint=item_constraint,
        flag=flag,
        flag_constraint=flag_constraint,
    )
