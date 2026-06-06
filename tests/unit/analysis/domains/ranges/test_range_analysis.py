import dis
from types import FunctionType
from unittest.mock import Mock, patch

from pysymex.analysis.domains.ranges.analyzer import RangeAnalyzer, ValueRangeChecker
from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState
from pysymex.analysis.domains.ranges.warnings import RangeWarning
from pysymex.analysis.domains.ranges.operations import transfer_call


def _compile_function(source: str, name: str = "target") -> FunctionType:
    namespace: dict[str, object] = {}
    exec(source, namespace)
    target = namespace[name]
    assert isinstance(target, FunctionType)
    return target


def _keyword_call_instruction() -> dis.Instruction:
    target = _compile_function("def target(func):\n    return func(value=1)\n")
    for instruction in dis.get_instructions(target):
        if instruction.opname == "CALL_KW":
            return instruction
    for instruction in dis.get_instructions(target):
        if instruction.opname == "CALL":
            return instruction
    raise AssertionError("keyword CALL not found")


def _call_function_ex_instruction(source: str) -> dis.Instruction:
    target = _compile_function(source)
    for instruction in dis.get_instructions(target):
        if instruction.opname == "CALL_FUNCTION_EX":
            return instruction
    raise AssertionError("CALL_FUNCTION_EX not found")


def _range_warnings_for(function: FunctionType) -> list[RangeWarning]:
    _, warnings = RangeAnalyzer().analyze(function.__code__, "range_branch_refinement.py")
    return warnings


def _mock_cfg(mock_cfg_builder: Mock) -> None:
    mock_instruction = Mock()
    mock_instruction.offset = 0
    mock_block = Mock()
    mock_block.instructions = [mock_instruction]
    mock_cfg = Mock()
    mock_cfg.blocks = {0: mock_block}
    mock_cfg.entry = mock_block
    mock_block.block_id = 0
    mock_block.successors = []
    mock_cfg_builder.return_value.build.return_value = mock_cfg


class TestRangeAnalyzer:
    """Test suite for pysymex.analysis.domains.ranges.RangeAnalyzer."""

    @patch("pysymex.analysis.domains.ranges.analyzer.CFGBuilder")
    def test_analyze(self, mock_cfg_builder: Mock) -> None:
        _mock_cfg(mock_cfg_builder)
        analyzer = RangeAnalyzer()
        code = compile("pass", "<string>", "exec")
        warnings = analyzer.analyze(code)
        assert isinstance(warnings, tuple)

    def test_branch_refinement_prunes_infeasible_negative_floor_division_zero(self) -> None:
        def target(x: int) -> int:
            if x < 0 and x > -4:
                q = x // 2
                if q == 0:
                    return 1 // 0
            return 0

        assert _range_warnings_for(target) == []

    def test_branch_refinement_keeps_feasible_floor_division_zero_warning(self) -> None:
        def target(x: int) -> int:
            if x > -2 and x < 2:
                q = x // 2
                if q == 0:
                    return 1 // 0
            return 0

        warnings = _range_warnings_for(target)
        assert len(warnings) == 1
        assert warnings[0].kind == "DIVISION_BY_ZERO"

    def test_transfer_call_kw_pops_keyword_metadata_separately(self) -> None:
        instruction = _keyword_call_instruction()
        state = RangeState()
        state.stack = [Range.full(), Range.exact(1)]
        if instruction.opname == "CALL_KW":
            state.stack.append(Range.full())

        transfer_call(instruction, state)

        assert len(state.stack) == 1

    def test_transfer_call_function_ex_pops_splat_payload(self) -> None:
        state = RangeState()
        state.stack = [Range.full(), Range.full()]

        transfer_call(
            _call_function_ex_instruction("def target(func, args):\n    return func(*args)\n"),
            state,
        )

        assert len(state.stack) == 1

    def test_transfer_call_function_ex_pops_kwargs_payload(self) -> None:
        state = RangeState()
        state.stack = [Range.full(), Range.full(), Range.full()]

        transfer_call(
            _call_function_ex_instruction(
                "def target(func, args, kwargs):\n    return func(*args, **kwargs)\n"
            ),
            state,
        )

        assert len(state.stack) == 1


class TestValueRangeChecker:
    """Test suite for pysymex.analysis.domains.ranges.ValueRangeChecker."""

    @patch("pysymex.analysis.domains.ranges.analyzer.CFGBuilder")
    def test_check_function(self, mock_cfg_builder: Mock) -> None:
        _mock_cfg(mock_cfg_builder)
        checker = ValueRangeChecker()
        code = compile("pass", "<string>", "exec")
        assert isinstance(checker.check_function(code), list)

    def test_check_array_bounds(self) -> None:
        checker = ValueRangeChecker()
        result = checker.check_array_bounds(Range.exact(5), 4)
        assert result is not None
        assert "may be out of bounds" in result
