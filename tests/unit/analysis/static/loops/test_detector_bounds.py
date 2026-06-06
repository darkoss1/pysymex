import dis
from unittest.mock import Mock

from pysymex.analysis.static.loops.bounds import LoopBoundInference
from pysymex.analysis.static.loops.detector import LoopDetector
from pysymex.analysis.static.loops.types import LoopBound, LoopInfo
from pysymex.core.types.containers.sequences import SymbolicIterator

from .loop_fixtures import make_dummy_code


class TestLoopDetector:
    """Test suite for pysymex.analysis.static.loops.detector.LoopDetector."""

    def test_analyze_cfg(self) -> None:
        """Test analyze_cfg behavior."""
        detector = LoopDetector()
        code = make_dummy_code()
        instructions: list[dis.Instruction] = list(dis.get_instructions(code))
        loops = detector.analyze_cfg(instructions)
        assert isinstance(loops, list)
        assert len(loops) > 0
        assert isinstance(loops[0], LoopInfo)

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


class TestLoopBoundInference:
    """Test suite for pysymex.analysis.static.loops.bounds.LoopBoundInference."""

    def test_infer_bound(self) -> None:
        """Test infer_bound behavior."""
        inference = LoopBoundInference()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        state = Mock(stack=[], locals={}, memory={}, path_constraints=[])

        bound = inference.infer_bound(loop, state)
        assert isinstance(bound, LoopBound)
        assert inference.infer_bound(loop, state) is bound

    def test_infer_bound_from_runtime_iterator(self) -> None:
        """Loop bounds use the iterator representation produced by GET_ITER."""
        inference = LoopBoundInference()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        runtime_iterator = SymbolicIterator("iter", [1, 2, 3], index=1)
        state = Mock(stack=[runtime_iterator], locals={}, memory={}, path_constraints=[])

        bound = inference.infer_bound(loop, state)

        assert bound.exact == 2
