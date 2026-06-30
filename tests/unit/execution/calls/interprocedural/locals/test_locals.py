"""Tests for interprocedural callee default and local-variable assembly."""

from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.execution.calls.interprocedural.locals.defaults import (
    CalleeDefaultBindings,
    prepare_callee_default_bindings,
)
from pysymex._internal.execution.calls.interprocedural.locals.defaults import (
    CalleeDefaultBindings as CalleeDefaultBindingsOwner,
)
from pysymex._internal.execution.calls.interprocedural.locals.defaults import (
    prepare_callee_default_bindings as prepare_callee_default_bindings_owner,
)
from pysymex._internal.execution.calls.interprocedural.locals.locals import build_callee_local_vars
from pysymex._internal.execution.calls.interprocedural.locals.locals import (
    build_callee_local_vars as build_callee_local_vars_owner,
)


def test_interprocedural_locals_public_exports_point_to_direct_owners() -> None:
    assert CalleeDefaultBindings is CalleeDefaultBindingsOwner
    assert build_callee_local_vars is build_callee_local_vars_owner
    assert prepare_callee_default_bindings is prepare_callee_default_bindings_owner


def test_prepare_callee_default_bindings_materializes_positional_and_keyword_defaults() -> None:
    def sample(required: int, optional: list[int] = [1], *, flag: dict[str, bool] = {"x": True}):
        return required, optional, flag

    bindings = prepare_callee_default_bindings(
        VMState(),
        sample,
        sample.__code__,
        ("required", "optional"),
        ("flag",),
        2,
    )

    assert isinstance(bindings, CalleeDefaultBindings)
    assert isinstance(bindings.positional_defaults["optional"], SymbolicList)
    assert bindings.positional_defaults["optional"].name == "optional"
    assert "flag" in bindings.keyword_defaults


def test_build_callee_local_vars_populates_args_varargs_and_kwargs() -> None:
    def sample(a: int, b: int, *extra: int, k: int, **rest: int) -> None:
        return None

    state, new_locals = build_callee_local_vars(
        VMState(),
        sample,
        sample.__code__,
        "sample",
        (),
        [1, 2, 3, 4],
        {"k": 5, "other": 6},
        ("a", "b"),
        ("k",),
        2,
        {},
        {},
    )

    assert state is not None
    assert new_locals["a"] == 1
    assert new_locals["b"] == 2
    assert new_locals["k"] == 5
    assert isinstance(new_locals["extra"], SymbolicList)
    assert new_locals["rest"] == {"other": 6}


def test_build_callee_local_vars_copies_closure_cell_into_heap() -> None:
    def outer() -> object:
        closed = 10

        def inner() -> int:
            return closed

        return inner

    inner = outer()
    assert callable(inner)

    state, new_locals = build_callee_local_vars(
        VMState(),
        inner,
        inner.__code__,
        "inner",
        (),
        [],
        {},
        (),
        (),
        0,
        {},
        {},
    )

    closure_cell = new_locals["closed"]
    assert isinstance(closure_cell, SymbolicObject)
    assert state.load_heap(closure_cell.address) == 10
