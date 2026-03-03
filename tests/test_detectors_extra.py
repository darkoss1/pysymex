import dis

import sys

import pytest

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicValue, SymbolicNone

from pysymex.analysis.detectors import UnboundVariableDetector, NoneDereferenceDetector, IssueKind


def make_instruction(opname, argval):
    def dummy():
        pass

    template = next(dis.get_instructions(dummy))

    opcode = dis.opmap.get(opname, 0)

    return template._replace(
        opname=opname,
        opcode=opcode,
        argval=argval,
        argrepr=str(argval),
        arg=0,
    )


def test_unbound_variable_detector():
    state = VMState()

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

    instr = make_instruction("LOAD_ATTR", "foo")

    det = NoneDereferenceDetector()

    issue = det.check(state, instr, lambda: True)

    assert issue is not None

    assert issue.kind == IssueKind.NULL_DEREFERENCE


def test_none_dereference_detector_symbolic_value_is_none():
    state = VMState()

    val = SymbolicValue.from_const(None)

    state.push(val)

    instr = make_instruction("LOAD_ATTR", "bar")

    det = NoneDereferenceDetector()

    issue = det.check(state, instr, lambda: True)

    assert issue is not None

    assert issue.kind == IssueKind.NULL_DEREFERENCE
