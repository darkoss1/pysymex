from unittest.mock import Mock, patch

import z3

from pysymex._internal.core.solver.constraints.chain import ConstraintChain
from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.scheduling.loops.types import LoopInfo
from pysymex._internal.execution.scheduling.loops.widening import LoopWidening


class TestLoopWidening:
    """Test suite for pysymex._internal.execution.scheduling.loops.widening.LoopWidening."""

    def test_should_widen(self) -> None:
        """Changing locals provide recurrence evidence for widening."""
        widening = LoopWidening()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        old_state = VMState(local_vars={"x": 1})
        same_state = VMState(local_vars={"x": 1})
        changed_state = VMState(local_vars={"x": 2})

        assert widening.should_widen(old_state, same_state, loop) is False
        assert widening.should_widen(old_state, changed_state, loop) is True

    @patch("pysymex._internal.core.types.scalars.values.SymbolicValue.symbolic_int")
    def test_widen_state(self, mock_sym_int: Mock) -> None:
        """Test widen_state behavior."""
        mock_sym_int.return_value = (Mock(z3_int=z3.Int("x_widened")), z3.BoolVal(True))
        widening = LoopWidening()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})

        old_val = object()
        new_val = Mock(affinity_type="int")
        old_state = Mock()
        old_state.local_vars = {"x": old_val}

        new_state = Mock()
        new_state.copy.return_value = new_state
        new_state.local_vars = {"x": new_val}
        new_state.path_constraints = ConstraintChain.empty()

        widened = widening.widen_state(old_state, new_state, loop)
        assert "x" in widened.local_vars
