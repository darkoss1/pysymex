from __future__ import annotations

import dis

from pysymex.analysis.detectors import KeyErrorDetector, NoneDereferenceDetector
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue
from pysymex.core.types_containers import SymbolicDict


def _make_instruction(opname: str, argval: object) -> dis.Instruction:
    def _dummy() -> None:
        return None

    template = next(dis.get_instructions(_dummy))
    opcode = dis.opmap.get(opname, 0)
    return template._replace(
        opname=opname,
        opcode=opcode,
        arg=0,
        argval=argval,
        argrepr=str(argval),
    )


def test_key_error_detector_handles_concrete_string_key() -> None:
    state = VMState()
    d = SymbolicDict.empty("d")
    state.push(d)
    state.push("missing")

    detector = KeyErrorDetector()
    issue = detector.check(state, _make_instruction("BINARY_SUBSCR", None), lambda _: True)

    assert issue is not None
    assert issue.kind.name == "KEY_ERROR"


def test_none_deref_skips_self_prefixed_symbolic_names() -> None:
    state = VMState()
    obj, _ = SymbolicValue.symbolic("self.user")
    state.push(obj)

    detector = NoneDereferenceDetector()
    issue = detector.check(state, _make_instruction("LOAD_ATTR", "name"), lambda _: True)

    assert issue is None
