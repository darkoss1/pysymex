"""Tests for analysis module bugfixes.

Each test class targets a specific confirmed bug from the analysis audit.
"""

from __future__ import annotations

import pytest
import z3
import inspect


# ---------------------------------------------------------------------------
# Bug 2B: Greedy loop bound inference grabs first matching constraint
# ---------------------------------------------------------------------------

class TestGreedyLoopBound:
    """LoopBoundInference should prefer later constraints (loop exit) over earlier."""

    def test_reverse_iteration_prefers_last_constraint(self):
        """After fix: reversed() iteration means the LAST constraint wins.

        Given path_constraints = [i < 5 (pre-loop), i < limit (loop exit)],
        the loop bound should be `limit`, not `5`.
        """
        from pysymex.analysis.loops.core import LoopBoundInference
        from pysymex.analysis.loops.types import InductionVariable, LoopBound, LoopInfo
        from unittest.mock import MagicMock

        i_var = z3.Int("i")
        limit = z3.Int("limit")

        # Two constraints: first is pre-loop assertion, second is loop exit
        constraint_assert = i_var < 5       # Pre-loop assertion (added first)
        constraint_loop = i_var < limit     # Loop exit (added last)

        mock_state = MagicMock()
        mock_state.path_constraints = [constraint_assert, constraint_loop]
        mock_state.stack = []
        mock_state.locals = {"i": MagicMock(z3_int=i_var)}
        mock_state.memory = MagicMock()
        mock_state.memory.items.return_value = []

        loop = LoopInfo(
            header_pc=10,
            back_edge_pc=30,
            exit_pcs={40},
            body_pcs={10, 20, 30},
        )
        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
                direction=1,
            )
        }

        inference = LoopBoundInference()
        bound = inference._infer_counted_bound(loop, mock_state)

        # After fix: bound.upper should be `limit` (the LAST matching constraint)
        assert bound.upper is not None
        assert z3.eq(bound.upper, limit), (
            f"Expected bound to reference 'limit', got '{bound.upper}'"
        )


# ---------------------------------------------------------------------------
# Bug 3: ReachingDefinitions ignores DELETE_FAST / DELETE_NAME
# ---------------------------------------------------------------------------

class TestDeleteNotHandled:
    """ReachingDefinitions must kill definitions on DELETE_FAST/DELETE_NAME."""

    def test_transfer_kills_on_delete(self):
        """The block-level transfer function should kill x after DELETE_FAST."""
        from pysymex.analysis.dataflow.core import Definition, ReachingDefinitions
        from pysymex.analysis.cfg import BasicBlock, ControlFlowGraph

        # Build a single-block CFG: STORE_FAST x at pc=0, DELETE_FAST x at pc=2
        def _make_instr(opname, opcode, argval, offset, line):
            """Create a dis.Instruction compatible with current Python version."""
            import dis
            params = set(inspect.signature(dis.Instruction).parameters)
            kwargs: dict[str, object] = {
                "opname": opname,
                "opcode": opcode,
                "arg": 0,
                "argval": argval,
                "argrepr": str(argval),
                "offset": offset,
            }
            if "start_offset" in params:
                kwargs["start_offset"] = offset
            if "starts_line" in params:
                kwargs["starts_line"] = True if "line_number" in params else line
            if "line_number" in params:
                kwargs["line_number"] = line
            if "is_jump_target" in params:
                kwargs["is_jump_target"] = False
            if "positions" in params:
                kwargs["positions"] = None
            if "cache_info" in params:
                kwargs["cache_info"] = None
            if "label" in params:
                kwargs["label"] = None
            if "baseopname" in params:
                kwargs["baseopname"] = opname
            if "baseopcode" in params:
                kwargs["baseopcode"] = opcode
            return dis.Instruction(**kwargs)

        block = BasicBlock(id=0, start_pc=0, end_pc=4)
        block.instructions = [
            _make_instr("STORE_FAST", 125, "x", 0, 1),
            _make_instr("DELETE_FAST", 126, "x", 2, 2),
            _make_instr("LOAD_FAST", 124, "x", 4, 3),
        ]

        cfg = ControlFlowGraph()
        cfg.blocks[0] = block
        cfg.entry_block_id = 0
        cfg.exit_block_ids = {0}
        # Register PCs
        for pc in range(0, 5):
            cfg.pc_to_block[pc] = 0
        # Compute dominators for the single block
        cfg.dominators[0] = {0}

        rd = ReachingDefinitions(cfg)
        rd.analyze()

        # Get reaching defs at pc=4 (the LOAD_FAST after DELETE_FAST)
        reaching = rd.get_reaching_defs_at(4)
        x_defs = {d for d in reaching if d.var_name == "x"}

        # After fix: no definition of x should reach after DELETE_FAST
        assert len(x_defs) == 0, (
            f"Definition of 'x' should NOT reach past DELETE_FAST, "
            f"but {len(x_defs)} definition(s) still arrive"
        )

    def test_transfer_function_directly(self):
        """Test the transfer function in isolation to verify DELETE kills defs."""
        from pysymex.analysis.dataflow.core import Definition, ReachingDefinitions
        from pysymex.analysis.cfg import BasicBlock, ControlFlowGraph

        def _make_instr(opname, opcode, argval, offset, line):
            import dis

            params = set(inspect.signature(dis.Instruction).parameters)
            kwargs: dict[str, object] = {
                "opname": opname,
                "opcode": opcode,
                "arg": 0,
                "argval": argval,
                "argrepr": str(argval),
                "offset": offset,
            }
            if "start_offset" in params:
                kwargs["start_offset"] = offset
            if "starts_line" in params:
                kwargs["starts_line"] = True if "line_number" in params else line
            if "line_number" in params:
                kwargs["line_number"] = line
            if "is_jump_target" in params:
                kwargs["is_jump_target"] = False
            if "positions" in params:
                kwargs["positions"] = None
            if "cache_info" in params:
                kwargs["cache_info"] = None
            if "label" in params:
                kwargs["label"] = None
            if "baseopname" in params:
                kwargs["baseopname"] = opname
            if "baseopcode" in params:
                kwargs["baseopcode"] = opcode
            return dis.Instruction(**kwargs)

        block = BasicBlock(id=0, start_pc=0, end_pc=2)
        block.instructions = [
            _make_instr("STORE_FAST", 125, "x", 0, 1),
            _make_instr("DELETE_FAST", 126, "x", 2, 2),
        ]

        cfg = ControlFlowGraph()
        cfg.blocks[0] = block
        cfg.entry_block_id = 0
        cfg.exit_block_ids = {0}
        cfg.dominators[0] = {0}

        rd = ReachingDefinitions(cfg)

        # Call transfer directly with empty in_fact
        out = rd.transfer(block, frozenset())

        # After STORE_FAST x, there would be one def. After DELETE_FAST x, zero.
        x_defs = {d for d in out if d.var_name == "x"}
        assert len(x_defs) == 0, (
            f"Expected 0 defs of 'x' after DELETE, got {len(x_defs)}"
        )


# ---------------------------------------------------------------------------
# Bug 1A: State merger injects SymbolicNone for missing attributes
# ---------------------------------------------------------------------------

class TestMergerSymbolicNone:
    """Merging states with different attributes must NOT inject SymbolicNone."""

    def test_missing_attr_source_code_no_symbolic_none(self):
        """Verify the source code no longer imports/uses SymbolicNone for merging."""
        import inspect
        from pysymex.analysis import state_merger

        source = inspect.getsource(state_merger)

        # After fix, the merge_memory section should NOT contain SymbolicNone
        # Count occurrences of SymbolicNone in the merge area
        lines = source.split('\n')
        merge_area = False
        symbolic_none_in_merge = False
        for line in lines:
            if 'v1 is not None' in line or 'v2 is not None' in line:
                merge_area = True
            if merge_area and 'SymbolicNone' in line:
                symbolic_none_in_merge = True
                break
            if merge_area and ('def ' in line and not line.strip().startswith('#')):
                merge_area = False

        assert not symbolic_none_in_merge, (
            "SymbolicNone is still used in attribute merge logic — "
            "this is unsound (missing attrs raise AttributeError, not return None)"
        )


# ---------------------------------------------------------------------------
# Bug 7B: infer_binary_op_type missing list*int, tuple*int, bytes*int
# ---------------------------------------------------------------------------

class TestMissingSequenceMultiplications:
    """TypeConstraintChecker.infer_binary_op_type must handle seq*int patterns."""

    @pytest.fixture
    def checker(self):
        from pysymex.analysis.type_constraints import TypeConstraintChecker
        return TypeConstraintChecker()

    def test_str_times_int_baseline(self, checker):
        """Baseline: str * int should be str (already works)."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeIssueKind
        result_type, issues = checker.infer_binary_op_type(
            SymbolicType.str_type(), SymbolicType.int_type(), "*"
        )
        assert result_type.kind.name == "STR"
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_list_times_int(self, checker):
        """[0] * 100 should produce list type, not INCOMPATIBLE_TYPES."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        list_type = SymbolicType(kind=TypeKind.LIST, name="list")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(list_type, int_type, "*")
        assert result_type.kind == TypeKind.LIST, f"Expected LIST, got {result_type.kind}"
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_int_times_list(self, checker):
        """100 * [0] should also produce list type."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        list_type = SymbolicType(kind=TypeKind.LIST, name="list")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(int_type, list_type, "*")
        assert result_type.kind == TypeKind.LIST
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_tuple_times_int(self, checker):
        """(1, 2) * 3 should produce tuple type."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        tuple_type = SymbolicType(kind=TypeKind.TUPLE, name="tuple")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(tuple_type, int_type, "*")
        assert result_type.kind == TypeKind.TUPLE
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_int_times_tuple(self, checker):
        """3 * (1, 2) should produce tuple type."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        tuple_type = SymbolicType(kind=TypeKind.TUPLE, name="tuple")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(int_type, tuple_type, "*")
        assert result_type.kind == TypeKind.TUPLE
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_bytes_times_int(self, checker):
        """b'\\x00' * 10 should produce bytes type."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        bytes_type = SymbolicType(kind=TypeKind.BYTES, name="bytes")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(bytes_type, int_type, "*")
        assert result_type.kind == TypeKind.BYTES
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)

    def test_int_times_bytes(self, checker):
        """10 * b'\\x00' should produce bytes type."""
        from pysymex.analysis.type_constraints.types import SymbolicType, TypeKind, TypeIssueKind
        bytes_type = SymbolicType(kind=TypeKind.BYTES, name="bytes")
        int_type = SymbolicType.int_type()

        result_type, issues = checker.infer_binary_op_type(int_type, bytes_type, "*")
        assert result_type.kind == TypeKind.BYTES
        assert not any(i.kind == TypeIssueKind.INCOMPATIBLE_TYPES for i in issues)


# ---------------------------------------------------------------------------
# Bug 2A: Int/Real sort mismatch — NOT A BUG in current Z3 version
# ---------------------------------------------------------------------------

class TestAccumulatorSortMismatch:
    """Document that Z3 Int / Int stays IntSort in this version (not a bug)."""

    def test_z3_int_div_stays_int_sort(self):
        """In current Z3, Int / Int produces IntSort (integer division)."""
        n = z3.Int("n")
        expr = (n * (n - z3.IntVal(1))) / z3.IntVal(2)
        assert expr.sort() == z3.IntSort(), (
            f"Unexpected: Z3 Int/Int produced {expr.sort()}, expected IntSort"
        )

    def test_accumulator_math_correctness(self):
        """Verify the arithmetic series formula produces correct results."""
        n = z3.Int("n")
        sum_n = (n * (n - z3.IntVal(1))) / z3.IntVal(2)
        s = z3.Solver()
        s.add(n == 5)
        assert s.check() == z3.sat
        assert s.model().eval(sum_n).as_long() == 10
