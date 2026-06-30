from __future__ import annotations

import dis

import z3

import pysymex._internal.execution.opcodes.py311.functions as functions
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def _instr(opname: str, argval: object = None, arg: int | None = None) -> dis.Instruction:
    # Get a base instruction to clone
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg)


def test_handle_call_stack_resilience() -> None:
    """Test that handle_call swaps func_obj and receiver_or_null if they are swapped."""
    # Scenario: func_obj is None/NULL (SymbolicNone) and receiver is an imported function
    id_suffix = 12345
    import_name = "import_loop_last"
    z3_addr = z3.Int(f"{import_name}_{id_suffix}_addr")
    # This receiver looks like a callable (starts with import_)
    receiver = SymbolicObject(
        _name=import_name, address=id_suffix, z3_addr=z3_addr, potential_addresses={id_suffix}
    )

    # Push items: [import_loop_last, NULL]
    state = VMState(stack=[receiver, SymbolicNone()], pc=0)

    result = functions.handle_call(_instr("CALL", 0), state, OpcodeDispatcher())

    assert not any(issue.kind == IssueKind.TYPE_ERROR for issue in result.issues)
    assert state.pc == 1


def test_handle_import_name_relative() -> None:
    """Test that IMPORT_NAME handles levels > 0 correctly."""
    state = VMState(stack=[1, SymbolicNone()], pc=0)
    state = state.set_global("__package__", "rich")

    # Relative lookup scenario for name resolution at level 1.
    functions.handle_import_name(_instr("IMPORT_NAME", "box", arg=1), state, OpcodeDispatcher())

    top = state.peek()
    assert isinstance(top, SymbolicObject)
    assert top.name == "rich.box"


def test_handle_load_method_inference() -> None:
    """Test that LOAD_METHOD correctly identifies a dictionary from its Z3 discriminator."""
    # Create a symbolic value that is CONCRETELY a dict
    sym_val = SymbolicValue(
        z3_int=z3.Int("maybe_dict_int"),
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_dict=Z3_TRUE,
        _name="maybe_dict",
    )
    state = VMState(stack=[sym_val], pc=0)

    # LOAD_METHOD "get"
    functions.handle_load_method(_instr("LOAD_METHOD", "get"), state, OpcodeDispatcher())

    top = state.peek()
    assert isinstance(top, SymbolicValue)
    assert top.model_name == "dict.get"
