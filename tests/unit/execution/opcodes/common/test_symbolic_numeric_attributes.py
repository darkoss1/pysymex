from __future__ import annotations

import dis
from pathlib import Path

import z3

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.common.functions import handle_common_load_method
from pysymex.scanner.file import scan_file


def _instr(opname: str, argval: object = None, arg: int | None = None) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, arg=arg, argval=argval)


def test_symbolic_int_load_attr_resolves_bit_count_model() -> None:
    value, type_constraint = SymbolicValue.symbolic_int("value")
    state = VMState(stack=[value], pc=7).add_constraint(type_constraint)

    result = handle_common_load_method(
        _instr("LOAD_ATTR", "bit_count"),
        state,
        OpcodeDispatcher(),
    )

    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.model_name == "int.bit_count"
    solver = z3.Solver()
    solver.add(*result.new_states[0].path_constraints.to_list(), loaded.is_none)
    assert solver.check() == z3.unsat


def test_simplifiable_symbolic_int_load_attr_resolves_bit_count_model() -> None:
    """Receivers with simplifiably-true int flags still use int method models."""
    value = SymbolicValue(
        _name="mixed",
        z3_int=z3.Int("mixed_int"),
        is_int=z3.Or(z3.BoolVal(True), z3.Bool("mixed_unused_type_flag")),
        z3_bool=z3.Bool("mixed_bool"),
        is_bool=z3.BoolVal(False),
    )
    state = VMState(stack=[value], pc=7)

    result = handle_common_load_method(
        _instr("LOAD_ATTR", "bit_count"),
        state,
        OpcodeDispatcher(),
    )

    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.model_name == "int.bit_count"


def test_scan_file_uses_symbolic_int_bit_count_model_without_havoc(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_bit_count.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    if value == 0 and value.bit_count() == 0:\n"
        "        return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_paths=40, timeout=4)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
