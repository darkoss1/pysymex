from pysymex._internal.execution.scheduling.loops.types import LoopInfo


class TestLoopInfo:
    """Test suite for pysymex._internal.execution.scheduling.loops.types.LoopInfo."""

    def test_contains_pc(self) -> None:
        """Test contains_pc behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.contains_pc(10) is True
        assert info.contains_pc(15) is True
        assert info.contains_pc(99) is False

    def test_is_header(self) -> None:
        """Test is_header behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.is_header(10) is True
        assert info.is_header(15) is False

    def test_is_exit(self) -> None:
        """Test is_exit behavior."""
        info = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 15, 20})
        assert info.is_exit(30) is True
        assert info.is_exit(20) is False
