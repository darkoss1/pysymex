"""Synthetic detector invocation fallback for runtime detector benchmark cases."""

from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex.typing import StackValue
from pysymex.analysis.detectors import default_registry
from pysymex.core.state.record import VMState
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from tests.repro.detector_benchmark_types import BenchmarkCase


def template_instruction() -> dis.Instruction:
    """Return a deterministic template instruction for synthetic detector fallback."""

    def _sentinel() -> None:
        """Provide a stable instruction template source."""
        return None

    return next(dis.get_instructions(_sentinel))


def make_instruction(
    opname: str,
    *,
    argval: object = None,
    argrepr: str = "",
    arg: int = 0,
    offset: int = 0,
) -> dis.Instruction:
    """Create a deterministic instruction instance for detector fallback execution."""
    template = template_instruction()
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


def run_synthetic_case(case: BenchmarkCase) -> bool:
    """Evaluate one benchmark case using direct detector invocation fallback."""
    detector = default_registry.get(case.detector_name)
    if detector is None:
        raise ValueError(f"Unknown detector name: {case.detector_name}")

    if case.function_name == "assertion_error_positive":
        issue = detector.check(
            VMState(stack=[AssertionError], path_constraints=[], pc=1),
            make_instruction("RAISE_VARARGS", arg=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "assertion_error_negative":
        issue = detector.check(
            VMState(stack=[AssertionError], path_constraints=[], pc=1),
            make_instruction("RAISE_VARARGS", arg=0),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "attribute_error_positive":
        issue = detector.check(
            VMState(stack=[1], path_constraints=[], pc=2),
            make_instruction("LOAD_ATTR", argval="missing_attribute"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "attribute_error_negative":
        issue = detector.check(
            VMState(stack=[1], path_constraints=[], pc=2),
            make_instruction("LOAD_ATTR", argval="bit_length"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_positive":
        issue = detector.check(
            VMState(stack=[10, 0], path_constraints=[], pc=3),
            make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_negative":
        issue = detector.check(
            VMState(stack=[10, 2], path_constraints=[], pc=3),
            make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_path_explosion_positive":
        issue = detector.check(
            VMState(stack=[120, 0], path_constraints=[], pc=3),
            make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "division_by_zero_path_explosion_negative":
        issue = detector.check(
            VMState(stack=[120, 3], path_constraints=[], pc=3),
            make_instruction("BINARY_OP", argrepr="/"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "index_error_positive":
        index_symbol, _index_constraint = SymbolicValue.symbolic_int("idx")
        issue = detector.check(
            VMState(stack=[[1, 2, 3], index_symbol], path_constraints=[], pc=4),
            make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "index_error_negative":
        issue = detector.check(
            VMState(stack=[[1, 2, 3], 1], path_constraints=[], pc=4),
            make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "key_error_positive":
        issue = detector.check(
            VMState(stack=[{"a": 1}, "missing"], path_constraints=[], pc=5),
            make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "key_error_negative":
        issue = detector.check(
            VMState(stack=[{"a": 1}, "a"], path_constraints=[], pc=5),
            make_instruction("BINARY_SUBSCR"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "none_dereference_positive":
        issue = detector.check(
            VMState(stack=[SymbolicNone()], path_constraints=[], pc=6),
            make_instruction("LOAD_ATTR", argval="field"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "none_dereference_negative":
        issue = detector.check(
            VMState(stack=["safe"], path_constraints=[], pc=6),
            make_instruction("LOAD_ATTR", argval="upper"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "overflow_positive":
        left_symbol, left_constraint = SymbolicValue.symbolic_int("left")
        right_symbol, right_constraint = SymbolicValue.symbolic_int("right")
        constraints = [
            left_constraint,
            right_constraint,
            left_symbol.z3_int == 2**63 - 1,
            right_symbol.z3_int == 1,
        ]
        issue = detector.check(
            VMState(stack=[left_symbol, right_symbol], path_constraints=constraints, pc=7),
            make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "overflow_negative":
        issue = detector.check(
            VMState(stack=[1, 2], path_constraints=[], pc=7),
            make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name in {
        "resource_leak_positive",
        "resource_leak_path_explosion_positive",
    }:
        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, make_instruction("CALL", arg=0, argval=0), lambda _c: True)
        issue = detector.check(state, make_instruction("RETURN_VALUE"), lambda _c: True)
        return issue is not None
    if case.function_name in {
        "resource_leak_negative",
        "resource_leak_path_explosion_negative",
    }:

        class _CloseCallable:
            """Synthetic close callable for fallback detector case."""

            __name__ = "close"

            def __call__(self) -> None:
                return None

        state = VMState(stack=[open], path_constraints=[], pc=8)
        detector.check(state, make_instruction("CALL", arg=0, argval=0), lambda _c: True)
        state.stack = [cast(StackValue, _CloseCallable())]
        detector.check(state, make_instruction("CALL", arg=0, argval=0), lambda _c: True)
        issue = detector.check(state, make_instruction("RETURN_VALUE"), lambda _c: True)
        return issue is not None
    if case.function_name == "type_error_positive":
        issue = detector.check(
            VMState(stack=["left", 1], path_constraints=[], pc=9),
            make_instruction("BINARY_OP", argrepr="-"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "type_error_negative":
        issue = detector.check(
            VMState(stack=["left", "right"], path_constraints=[], pc=9),
            make_instruction("BINARY_OP", argrepr="+"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "unbound_variable_positive":
        issue = detector.check(
            VMState(stack=[], path_constraints=[], pc=10),
            make_instruction("LOAD_FAST", argval="local_value"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "unbound_variable_negative":
        state = VMState(stack=[], path_constraints=[], pc=10)
        state.set_local("local_value", z3.IntVal(1))
        issue = detector.check(
            state,
            make_instruction("LOAD_FAST", argval="local_value"),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_positive":
        issue = detector.check(
            VMState(stack=[int, "not-an-int"], path_constraints=[], pc=11),
            make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_negative":
        issue = detector.check(
            VMState(stack=[int, "42"], path_constraints=[], pc=11),
            make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_path_explosion_positive":
        issue = detector.check(
            VMState(stack=[int, "invalid-token"], path_constraints=[], pc=11),
            make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None
    if case.function_name == "value_error_path_explosion_negative":
        issue = detector.check(
            VMState(stack=[int, "233"], path_constraints=[], pc=11),
            make_instruction("CALL", arg=1, argval=1),
            lambda _constraints: True,
        )
        return issue is not None

    raise ValueError(f"No synthetic fallback defined for case: {case.function_name}")
