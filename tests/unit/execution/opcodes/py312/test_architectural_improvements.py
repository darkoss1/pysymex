from __future__ import annotations

import dis
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state import VMState
from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.scalars import SymbolicNone, SymbolicValue
from pysymex.core.types.containers import SymbolicObject
from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.execution.opcodes.py312 import functions, locals


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
    # Stack: [level, fromlist]
    state = VMState(stack=[1, SymbolicNone()], pc=0)
    state = state.set_global("__package__", "rich")

    # from . import box (level 1)
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


def test_handle_load_global_naming_heuristic() -> None:
    """Test that LOAD_GLOBAL with a name like _MAP applies the is_dict constraint concretely."""
    state = VMState(pc=0)

    # LOAD_GLOBAL _SUBSTITUTIONS
    locals.handle_load_global(
        _instr("LOAD_GLOBAL", "_SUBSTITUTIONS", arg=0), state, OpcodeDispatcher()
    )

    top = state.peek()
    assert isinstance(top, SymbolicValue)

    # Check if is_dict is concretely True
    assert z3.is_true(z3.simplify(top.is_dict))
