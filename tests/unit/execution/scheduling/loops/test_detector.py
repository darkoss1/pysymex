import dis

from pysymex._internal.execution.scheduling.loops.cfg import (
    build_cfg,
    compute_dominators,
    find_back_edges,
)
from pysymex._internal.execution.scheduling.loops.detector import LoopDetector
from pysymex._internal.execution.scheduling.loops.info import build_loop_info
from pysymex._internal.execution.scheduling.loops.types import LoopInfo

from .loop_fixtures import make_dummy_code


class TestLoopDetector:
    """Test suite for pysymex._internal.execution.scheduling.loops.detector.LoopDetector."""

    def test_analyze_cfg(self) -> None:
        """Test analyze_cfg behavior."""
        detector = LoopDetector()
        code = make_dummy_code()
        instructions: list[dis.Instruction] = list(dis.get_instructions(code))
        loops = detector.analyze_cfg(instructions)
        assert isinstance(loops, list)
        assert len(loops) > 0
        assert isinstance(loops[0], LoopInfo)

    def test_cfg_and_info_helpers_match_detector_loop(self) -> None:
        """Test helper owners produce the same loop metadata as LoopDetector."""
        detector = LoopDetector()
        code = make_dummy_code()
        instructions: list[dis.Instruction] = list(dis.get_instructions(code))
        loops = detector.analyze_cfg(instructions)
        assert len(loops) > 0

        cfg = build_cfg(instructions)
        dominators = compute_dominators(cfg, 0)
        back_edges = find_back_edges(cfg, dominators)
        expected_edge = (loops[0].back_edge_pc, loops[0].header_pc)

        assert expected_edge in back_edges
        helper_loop = build_loop_info(cfg, *expected_edge)
        assert helper_loop.header_pc == loops[0].header_pc
        assert helper_loop.back_edge_pc == loops[0].back_edge_pc
        assert helper_loop.exit_pcs == loops[0].exit_pcs
        assert helper_loop.body_pcs == loops[0].body_pcs

    def test_loops(self) -> None:
        """Test loops behavior."""
        detector = LoopDetector()
        assert detector.loops == []
        code = make_dummy_code()
        instructions: list[dis.Instruction] = list(dis.get_instructions(code))
        loops = detector.analyze_cfg(instructions)
        assert detector.loops == loops

    def test_get_loop_at(self) -> None:
        """Test get_loop_at behavior."""
        detector = LoopDetector()
        code = make_dummy_code()
        instructions: list[dis.Instruction] = list(dis.get_instructions(code))
        loops = detector.analyze_cfg(instructions)
        assert len(loops) > 0
        pc = list(loops[0].body_pcs)[0]
        assert detector.get_loop_at(pc) is loops[0]
        assert detector.get_loop_at(-1) is None

    def test_for_iter_exit_does_not_create_spurious_exit_loop(self) -> None:
        def loop(xs: list[int]) -> int:
            total = 0
            for x in xs:
                total += x
            return total

        instructions = list(dis.get_instructions(loop.__code__))
        for_iter = next(instr for instr in instructions if instr.opname == "FOR_ITER")
        jump_back = next(
            instr for instr in instructions if instr.opname.startswith("JUMP_BACKWARD")
        )

        detector = LoopDetector()
        loops = detector.analyze_cfg(instructions)

        assert [(loop_info.header_pc, loop_info.back_edge_pc) for loop_info in loops] == [
            (for_iter.offset, jump_back.offset)
        ]
        assert isinstance(for_iter.argval, int)
        assert for_iter.argval in loops[0].exit_pcs
