import dis

from pysymex.analysis.detectors import IssueKind, NoneDereferenceDetector, UnboundVariableDetector
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicNone, SymbolicValue


def make_instruction(opname, argval):
    # Robustly create instruction compatible with current Python version
    def dummy():
        pass

    # Get a template instruction from dummy function
    template = next(dis.get_instructions(dummy))

    # Modify fields using _replace (Instruction is a namedtuple)
    # We might need to set opcode if opname changes, but for detector logic only opname/argval matters usually.
    # Detectors check opname string.

    # Map opname to opcode if possible, or just use 0/fake.
    opcode = dis.opmap.get(opname, 0)

    return template._replace(
        opname=opname,
        opcode=opcode,
        argval=argval,
        argrepr=str(argval),
        arg=0,  # Some checks might rely on arg being int
    )


def test_unbound_variable_detector():
    state = VMState()
    # LOAD_FAST 'x' -> x is not in locals
    instr = make_instruction("LOAD_FAST", "x")

    det = UnboundVariableDetector()
    issue = det.check(state, instr, lambda: True)

    assert issue is not None
    assert issue.kind == IssueKind.UNBOUND_VARIABLE
    assert "x" in issue.message


def test_unbound_variable_detector_bound():
    state = VMState()
    state.set_local("y", SymbolicValue.from_const(1))
    instr = make_instruction("LOAD_FAST", "y")

    det = UnboundVariableDetector()
    issue = det.check(state, instr, lambda: True)

    assert issue is None


def test_none_dereference_detector_symbolic_none():
    state = VMState()
    state.push(SymbolicNone())
    # LOAD_ATTR 'foo' -> None.foo
    instr = make_instruction("LOAD_ATTR", "foo")

    det = NoneDereferenceDetector()
    issue = det.check(state, instr, lambda: True)

    assert issue is not None
    assert issue.kind == IssueKind.NULL_DEREFERENCE


def test_none_dereference_detector_symbolic_value_is_none():
    state = VMState()
    val = SymbolicValue.from_const(None)
    state.push(val)
    # LOAD_ATTR 'bar' -> None.bar
    instr = make_instruction("LOAD_ATTR", "bar")

    det = NoneDereferenceDetector()
    issue = det.check(state, instr, lambda: True)

    assert issue is not None
    assert issue.kind == IssueKind.NULL_DEREFERENCE
