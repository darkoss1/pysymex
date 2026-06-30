"""Tests for pysymex/_internal/analysis/detectors/specialized/formatting.py."""

from __future__ import annotations

import dis

import z3

from pysymex._internal.analysis.detectors.specialized.formatting import FormatStringDetector
from pysymex._internal.core.state.record import VMState


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

        from pysymex._internal.core.types.havoc import HavocValue

        havoc_val, _ = HavocValue.havoc("havoc_input")

        state = VMState(stack=[havoc_val], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INVALID_ARGUMENT"

    def test_check_reports_issue_for_havoc_format_with_spec_value(self) -> None:
        """Report INVALID_ARGUMENT when FORMAT_WITH_SPEC consumes a havoc value."""
        detector = FormatStringDetector()
        instruction = _make_instruction("FORMAT_WITH_SPEC")

        from pysymex._internal.core.types.havoc import HavocValue

        havoc_val, _ = HavocValue.havoc("havoc_value")

        state = VMState(stack=[havoc_val, ">10"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INVALID_ARGUMENT"

    def test_check_reports_issue_for_havoc_format_with_spec_spec(self) -> None:
        """Report INVALID_ARGUMENT when FORMAT_WITH_SPEC consumes a havoc spec."""
        detector = FormatStringDetector()
        instruction = _make_instruction("FORMAT_WITH_SPEC")

        from pysymex._internal.core.types.havoc import HavocValue

        havoc_spec, _ = HavocValue.havoc("havoc_spec")

        state = VMState(stack=[1, havoc_spec], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "INVALID_ARGUMENT"

    def test_check_reports_issue_for_havoc_build_string_operand_not_on_top(self) -> None:
        """Report INVALID_ARGUMENT when BUILD_STRING consumes any havoc operand."""
        detector = FormatStringDetector()
        instruction = _make_instruction("BUILD_STRING", arg=3)

        from pysymex._internal.core.types.havoc import HavocValue

        havoc_part, _ = HavocValue.havoc("havoc_part")

        state = VMState(stack=["prefix", havoc_part, "suffix"], path_constraints=[], pc=1)

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
