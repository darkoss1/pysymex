"""Tests for execution initial-state input mapping."""

from __future__ import annotations

from pathlib import Path

import z3

from pysymex._internal.config.execution.settings import ExecutionConfig
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.hints import canonicalize_symbolic_type_hint
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.initial.state.code.state import create_code_initial_state
from pysymex._internal.execution.initial.state.contracts import inject_initial_obligations
from pysymex._internal.execution.initial.state.factory.core import SymbolicInputFactory
from pysymex._internal.execution.initial.state.factory.nullable import (
    create_nullable_symbolic_for_type,
)
from pysymex._internal.execution.initial.state.hints import hint_to_type_str
from pysymex._internal.execution.session.state.core import ExecutionSession


def test_initial_contract_obligations_noop_when_contracts_disabled() -> None:
    def target() -> None:
        return None

    state = VMState()

    assert (
        inject_initial_obligations(
            state,
            target,
            config=ExecutionConfig(enable_contract_verification=False),
            session=ExecutionSession(),
        )
        is state
    )


def test_hint_to_type_str_uses_exact_type_identity() -> None:
    """Type names containing path should not become path-like hints."""

    class Empathic:
        pass

    assert hint_to_type_str(Path) == "path"
    assert hint_to_type_str(Empathic) == "int"
    assert hint_to_type_str(str | None) == "optional:str"
    assert hint_to_type_str(int | None) == "optional:int"
    assert hint_to_type_str(tuple[int, str]) == "tuple[int,str]"
    assert hint_to_type_str(bytes) == "bytes"
    assert hint_to_type_str(bytearray) == "bytearray"
    assert hint_to_type_str(set[int]) == "set"
    assert hint_to_type_str(frozenset[int]) == "frozenset"


def test_symbolic_type_hint_aliases_normalize_once() -> None:
    assert canonicalize_symbolic_type_hint(" INTEGER ") == "int"
    assert canonicalize_symbolic_type_hint("nullable:STRING") == "optional:str"
    assert canonicalize_symbolic_type_hint("tuple[INTEGER, STRING]") == "tuple[int,str]"


def test_nullable_symbolic_factory_allows_none_or_inner_type() -> None:
    value, constraint = create_nullable_symbolic_for_type("maybe_count", "int")
    constraint_text = str(constraint)

    assert isinstance(value, SymbolicValue)
    assert value.name == "maybe_count"
    assert str(value.is_none) in constraint_text
    assert str(value.is_int) in constraint_text


def test_symbolic_input_factory_delegates_nullable_type_hints() -> None:
    value, constraint = SymbolicInputFactory().create_symbolic_for_type(
        "maybe_name",
        "optional:str",
    )
    constraint_text = str(constraint)

    assert isinstance(value, SymbolicValue)
    assert value.name == "maybe_name"
    assert str(value.is_none) in constraint_text
    assert str(value.is_str) in constraint_text


def test_nullable_factory_covers_bytes_tuple_and_set_type_channels() -> None:
    cases = (
        ("bytes", "is_bytes"),
        ("tuple[int,str]", "is_tuple"),
        ("set", "is_set"),
    )
    for hint, type_attribute in cases:
        value, constraint = create_nullable_symbolic_for_type(f"maybe_{type_attribute}", hint)
        assert isinstance(value, SymbolicValue)
        type_branch = getattr(value, type_attribute)

        none_solver = z3.Solver()
        none_solver.add(constraint, value.is_none)
        assert none_solver.check() == z3.sat

        typed_solver = z3.Solver()
        typed_solver.add(constraint, type_branch)
        assert typed_solver.check() == z3.sat

    tuple_value, tuple_constraint = create_nullable_symbolic_for_type(
        "maybe_pair", "tuple[int,str]"
    )
    assert isinstance(tuple_value, SymbolicValue)
    wrong_length_solver = z3.Solver()
    wrong_length_solver.add(tuple_constraint, tuple_value.is_tuple, tuple_value.z3_int != 2)
    assert wrong_length_solver.check() == z3.unsat


def test_symbolic_input_factory_builds_inferred_bytes_carrier() -> None:
    value, constraint = SymbolicInputFactory().create_symbolic_for_type(
        "data", hint_to_type_str(bytes)
    )

    assert isinstance(value, SymbolicBytes)
    assert z3.is_true(constraint)


def test_symbolic_input_factory_preserves_fixed_tuple_elements() -> None:
    value, constraint = SymbolicInputFactory().create_symbolic_for_type(
        "pair",
        "tuple[int,str]",
    )

    assert isinstance(value, SymbolicTuple)
    assert len(value) == 2
    assert isinstance(value.elements[0], SymbolicValue)
    assert value.elements[0].affinity_type == "int"
    assert value.elements[0].name == "pair[0]"
    assert isinstance(value.elements[1], SymbolicString)
    assert value.elements[1].name == "pair[1]"
    assert not z3.is_false(simplify_expr(constraint))


def test_symbolic_input_factory_marks_unknown_tuple_hints_as_tuple_carriers() -> None:
    factory = SymbolicInputFactory()
    value, constraint = factory.create_symbolic_for_type("items", "tuple")
    state = factory.flush_temp_memory(VMState())

    assert not z3.is_false(simplify_expr(constraint))
    assert isinstance(value, SymbolicObject)
    stored_values = list(state.memory.values())
    assert len(stored_values) == 1
    stored = stored_values[0]
    assert isinstance(stored, SymbolicList)
    assert getattr(stored, "_type", None) == "tuple"


def test_create_code_initial_state_mirrors_module_symbolic_inputs_to_globals() -> None:
    code = compile("result = y\n", "<test>", "exec")

    state = create_code_initial_state(code, {"y": "int"})

    local_y = state.get_local("y")
    assert local_y is not None
    assert state.get_global("y") is local_y


def test_create_code_initial_state_seeds_builtin_names_for_code_execution() -> None:
    code = compile("raise RuntimeError('boom')\n", "<test>", "exec")

    state = create_code_initial_state(code)

    assert state.get_global("RuntimeError") is RuntimeError
    assert state.get_global("len") is len


def test_create_code_initial_state_initial_globals_override_builtin_names() -> None:
    code = compile("raise RuntimeError('boom')\n", "<test>", "exec")

    state = create_code_initial_state(code, initial_globals={"RuntimeError": ValueError})

    assert state.get_global("RuntimeError") is ValueError


def test_create_code_initial_state_models_mutable_container_globals() -> None:
    code = compile("result = GLOBAL_LIST\n", "<test>", "exec")

    state = create_code_initial_state(
        code,
        initial_globals={
            "GLOBAL_LIST": [1],
            "GLOBAL_DICT": {"seed": 1},
            "GLOBAL_SET": {1},
        },
    )

    global_list = state.get_global("GLOBAL_LIST")
    global_dict = state.get_global("GLOBAL_DICT")
    global_set = state.get_global("GLOBAL_SET")

    assert isinstance(global_list, SymbolicList)
    assert global_list.name == "GLOBAL_LIST"
    assert isinstance(global_dict, SymbolicDict)
    assert global_dict.name == "GLOBAL_DICT"
    assert isinstance(global_set, SymbolicValue)
    assert global_set.name == "GLOBAL_SET"


def test_create_code_initial_state_keeps_function_symbolic_inputs_local_only() -> None:
    def target(x: int) -> int:
        return x

    state = create_code_initial_state(target.__code__, {"x": "int"})

    assert state.get_local("x") is not None
    assert state.get_global("x") is None


def test_create_code_initial_state_inferred_inputs_yield_to_function_defaults() -> None:
    default_items: list[int] = []

    def target(x: int, items: list[int] = default_items) -> int:
        return x + len(items)

    explicit_state = create_code_initial_state(
        target.__code__,
        {"x": "int", "items": "list"},
        {target.__name__: target},
    )
    inferred_state = create_code_initial_state(
        target.__code__,
        {"x": "int", "items": "list"},
        {target.__name__: target},
        symbolic_vars_are_inferred=True,
    )

    explicit_items = explicit_state.get_local("items")
    inferred_items = inferred_state.get_local("items")

    assert not isinstance(explicit_items, SymbolicList)
    assert isinstance(inferred_items, SymbolicList)
    assert inferred_items.name == "items"
