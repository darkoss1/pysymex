from pysymex.analysis.detectors.base import IssueKind
import dis
from unittest.mock import Mock
from pysymex.analysis.detectors.base import (
    Issue,
    DetectorInfo,
    Detector,
    DetectorRegistry,
    IsSatFn,
)
from pysymex.core.state import VMState


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


class DummyDetector(Detector):
    name = "dummy"
    description = "dummy description"
    issue_kind = IssueKind.UNKNOWN

    def check(
        self, state: VMState, instruction: dis.Instruction, _solver_check: IsSatFn
    ) -> Issue | None:
        return None


class TestIssueKind:
    """Test suite for pysymex.analysis.detectors.base.IssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IssueKind.DIVISION_BY_ZERO.name == "DIVISION_BY_ZERO"


class TestIssue:
    """Test suite for pysymex.analysis.detectors.base.Issue."""

    def test_get_counterexample(self) -> None:
        """Test get_counterexample behavior."""
        issue1 = Issue(IssueKind.UNKNOWN, "msg")
        assert issue1.get_counterexample() == {}

        issue2 = Issue(IssueKind.UNKNOWN, "msg", counterexample={"x": 1})
        assert issue2.get_counterexample() == {"x": 1}

    def test_format(self) -> None:
        """Test format behavior."""
        issue = Issue(IssueKind.UNKNOWN, "msg", filename="test.py", line_number=10, pc=5)
        fmt = issue.format()
        assert "[UNKNOWN] msg" in fmt
        assert "Location: test.py, line 10" in fmt
        assert "PC: 5" in fmt

    def test_to_dict(self) -> None:
        """Test to_dict behavior."""
        issue = Issue(IssueKind.UNKNOWN, "msg", pc=5)
        d = issue.to_dict()
        assert d["kind"] == "UNKNOWN"
        assert d["message"] == "msg"
        assert d["pc"] == 5


class TestDetectorInfo:
    """Test suite for pysymex.analysis.detectors.base.DetectorInfo."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        info = DetectorInfo("name", "desc", IssueKind.UNKNOWN)
        assert info.name == "name"


class TestDetector:
    """Test suite for pysymex.analysis.detectors.base.Detector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = DummyDetector()
        assert d.check(Mock(), Mock(), Mock()) is None

    def test_to_info(self) -> None:
        """Test to_info behavior."""
        d = DummyDetector()
        info = d.to_info()
        assert info.name == "dummy"
        assert info.issue_kind == IssueKind.UNKNOWN

    def test_as_fn(self) -> None:
        """Test as_fn behavior."""
        d = DummyDetector()
        fn = d.as_fn()
        assert fn(Mock(), Mock(), Mock()) is None


class TestDetectorRegistry:
    """Test suite for pysymex.analysis.detectors.base.DetectorRegistry."""

    def test_register(self) -> None:
        """Test register behavior."""
        r = DetectorRegistry()
        r.register(DummyDetector)
        assert "dummy" in r._detectors  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    def test_register_fn(self) -> None:
        """Test register_fn behavior."""
        r = DetectorRegistry()

        def dummy_fn(
            _state: VMState, _instruction: dis.Instruction, _is_satisfiable: IsSatFn
        ) -> Issue | None:
            return None

        info = DetectorInfo("dfn", "desc", IssueKind.UNKNOWN)
        r.register_fn(dummy_fn, info)
        assert "dfn" in r._fn_detectors  # type: ignore[reportPrivateUsage]  # white-box test requires access to internal state

    def test_get_all_fns(self) -> None:
        """Test get_all_fns behavior."""
        r = DetectorRegistry()

        def dummy_fn(
            _state: VMState, _instruction: dis.Instruction, _is_satisfiable: IsSatFn
        ) -> Issue | None:
            return None

        info = DetectorInfo("test_fn", "test description", IssueKind.UNKNOWN)
        r.register_fn(dummy_fn, info)

        fns = r.get_all_fns()
        assert len(fns) > 0
        assert fns[0][0] is dummy_fn
        assert fns[0][1] is info
