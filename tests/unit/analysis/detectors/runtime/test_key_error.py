"""Tests for pysymex/analysis/detectors/runtime/key_error.py."""

from __future__ import annotations

import dis

from pysymex.analysis.detectors.runtime.key_error import KeyErrorDetector
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.core.types.containers import SymbolicDict


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create a deterministic instruction for detector unit tests."""

    def _dummy() -> None:
        """Provide bytecode for a template instruction."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestKeyErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.KeyErrorDetector."""

    def test_check_reports_missing_key_for_concrete_dict(self) -> None:
        """Report KEY_ERROR for concrete dictionaries missing the requested key."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[{"present": 1}, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_existing_key_for_concrete_dict(self) -> None:
        """Return None when concrete dictionary key exists."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[{"present": 1}, "present"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_missing_key_for_symbolic_dict_string_key(self) -> None:
        """Report KEY_ERROR for symbolic dictionaries when string key may be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("sym_dict")
        state = VMState(
            stack=[symbolic_dict, SymbolicString.from_const("missing")],
            path_constraints=[],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_symbolic_value_string_key(self) -> None:
        """Report KEY_ERROR when key is represented as SymbolicValue constrained to string."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.empty("sym_dict")
        symbolic_key = SymbolicValue.from_const("missing")
        state = VMState(stack=[symbolic_dict, symbolic_key], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_non_dict_container(self) -> None:
        """Return None when container is not a dictionary."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        state = VMState(stack=[[1, 2, 3], "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_symbolic_dict_concrete_items_present_key_no_issue(self) -> None:
        """Do not report KEY_ERROR when symbolic dict has concrete backing and key exists."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        state = VMState(stack=[symbolic_dict, "present"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_symbolic_dict_concrete_items_missing_key_reports(self) -> None:
        """Report KEY_ERROR when symbolic dict has concrete backing and key is missing."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        state = VMState(stack=[symbolic_dict, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_symbolic_dict_concrete_items_symbolic_key_reports(self) -> None:
        """Report KEY_ERROR when concrete-backed SymbolicDict is indexed by symbolic key."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("BINARY_SUBSCR")
        symbolic_dict = SymbolicDict.from_const({"present": 1})
        symbolic_key, _symbolic_constraint = SymbolicString.symbolic("k")
        state = VMState(stack=[symbolic_dict, symbolic_key], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_delete_subscr(self) -> None:
        """Report KEY_ERROR for DELETE_SUBSCR when key can be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("DELETE_SUBSCR")
        state = VMState(stack=[{"present": 1}, "missing"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_key_for_dict_pop_call(self) -> None:
        """Report KEY_ERROR for dict.pop call when key can be absent."""
        detector = KeyErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        class _PopCallable:
            __name__ = "mapping.pop"

            def __call__(self) -> None:
                return None

        state = VMState(
            stack=[_PopCallable(), {"present": 1}, "missing"], path_constraints=[], pc=1
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None
