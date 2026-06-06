"""Tests for pysymex/analysis/detectors/specialized/format_string.py."""

from __future__ import annotations

import dis
import z3
from pysymex.analysis.detectors.specialized.format_string import FormatStringDetector
from pysymex.core.state.record import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic bytecode instructions for detector tests."""

    def _dummy() -> None:
        """Provide a stable instruction template."""
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


class TestFormatStringDetector:
    """Test suite for specialized FormatStringDetector behavior."""

    def test_check_returns_none_when_stack_is_empty(self) -> None:
        """Return None when processing a formatting opcode with an empty stack."""
        detector = FormatStringDetector()
        instruction = _make_instruction("FORMAT_VALUE")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_returns_none_for_concrete_string_formatting(self) -> None:
        """Return None when formatting a concrete string value."""
        detector = FormatStringDetector()
        instruction = _make_instruction("FORMAT_VALUE")
        state = VMState(stack=["concrete"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_reports_issue_for_havoc_string_formatting(self) -> None:
        """Report INVALID_ARGUMENT when an unconstrained symbolic string is formatted."""
        detector = FormatStringDetector()
        instruction = _make_instruction("FORMAT_VALUE")

        from pysymex.core.types.havoc import HavocValue

        havoc_val, _ = HavocValue.havoc("havoc_input")

        state = VMState(stack=[havoc_val], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INVALID_ARGUMENT"

    def test_check_ignores_unrelated_opcode(self) -> None:
        """Return None when processing opcodes not related to string formatting."""
        detector = FormatStringDetector()
        instruction = _make_instruction("LOAD_CONST")
        state = VMState(stack=["value"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None
