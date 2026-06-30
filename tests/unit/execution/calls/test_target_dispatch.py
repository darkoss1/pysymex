"""Tests for resolved call-target dispatch package exports."""

from __future__ import annotations

import dis

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.execution.calls.target.dispatch.expanded import dispatch_expanded_call_target
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def test_expanded_call_target_reports_definite_non_callable() -> None:
    instr = _sample_instruction()

    result = dispatch_expanded_call_target(
        instr,
        VMState(pc=instr.offset),
        OpcodeDispatcher(),
        1,
        [],
        {},
    )

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'int' object is not callable" in result.issues[0].message


def test_expanded_call_target_uses_shared_symbolic_affinities() -> None:
    instr = _sample_instruction()
    targets = (
        (SymbolicBytes.symbolic("data"), "bytes"),
        (SymbolicTuple.from_elements(), "tuple"),
        (SymbolicSet.from_const(set()), "set"),
    )
    for target, type_name in targets:
        result = dispatch_expanded_call_target(
            instr,
            VMState(pc=instr.offset),
            OpcodeDispatcher(),
            target,
            [],
            {},
        )

        assert result.terminal is True
        assert f"'{type_name}' object is not callable" in result.issues[0].message


def _sample_instruction() -> dis.Instruction:
    def sample() -> None:
        return None

    return next(dis.get_instructions(sample))
