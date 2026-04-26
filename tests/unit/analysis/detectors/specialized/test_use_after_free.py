from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/specialized/use_after_free.py."""

from unittest.mock import Mock
import dis
from pysymex.analysis.detectors.specialized.use_after_free import UseAfterFreeDetector


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestUseAfterFreeDetector:
    """Test suite for pysymex.analysis.detectors.specialized.UseAfterFreeDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = UseAfterFreeDetector()

        # Create a mock object with a proper name property
        class MockObj:
            @property
            def name(self) -> str:
                return "file_obj"

        obj = MockObj()
        instr1 = MockInstr("CALL", arg=0)
        state1 = Mock(stack=[obj, Mock(qualname="file_obj.close")])
        d.check(state1, instr1, lambda c: True)

        instr2 = MockInstr("LOAD_METHOD")
        state2 = Mock(stack=[obj], pc=1)
        state2.peek.return_value = obj
        issue = d.check(state2, instr2, lambda c: True)
        # After calling close(), using the object should trigger use-after-free detection
        assert issue is not None
        assert issue.kind == IssueKind.ATTRIBUTE_ERROR
