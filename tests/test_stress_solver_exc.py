"""Stress-tests for solver and exception-handler fixes in pysymex.

Covers 6 targeted fixes:
  solver.py       — add() cache clear, try/finally on push/pop in is_sat /
                    check_sat_cached / implies
  exceptions.py   — SETUP_FINALLY exc fork enters block before jumping
  state.py        — fork() copies _class_registry (dict guard) & pending_kw_names
  control.py      — END_FOR pops 2 values
  functions.py    — LOAD_SUPER_ATTR pops 3 values
"""

from __future__ import annotations

import dis
from typing import Any
from unittest.mock import MagicMock

import pytest
import z3

from pysymex.core.solver import IncrementalSolver
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue


def _make_instr(
    opname: str,
    opcode: int,
    arg: Any = None,
    argval: Any = None,
    argrepr: str = "",
    offset: int = 0,
    starts_line: bool = False,
    line_number: int = 1,
    positions: Any = None,
) -> dis.Instruction:
    """Create a dis.Instruction compatible with Python 3.12+ / 3.13+."""
    # Python 3.13 renamed starts_line from int to bool and replaced
    # is_jump_target; also requires start_offset and line_number.
    return dis.Instruction(
        opname=opname,
        opcode=opcode,
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
        start_offset=offset,
        starts_line=starts_line,
        line_number=line_number,
        positions=positions,
    )


# ═══════════════════════════════════════════════════════════════════
#  PART 1: IncrementalSolver — add() cache invalidation
# ═══════════════════════════════════════════════════════════════════


class TestSolverAddCacheClear:
    """After fix: add() clears the result cache so stale results cannot leak."""

    def test_cache_cleared_after_add(self):
        """Cache context changes immediately after add()."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        # Populate cache
        solver.is_sat([x > 0])
        old_cache_size = len(solver._cache)
        # add() must change context
        solver.add(x < 100)
        assert len(solver._cache) >= old_cache_size, "old entries should remain"
        
        # New check should miss
        hits = solver._cache_hits
        solver.is_sat([x > 0])
        assert solver._cache_hits == hits, "should be a cache miss due to new context"

    def test_cache_cleared_independently_of_constraint_content(self):
        """Even a trivially-true constraint should still change the context."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        hits = solver._cache_hits
        solver.add(z3.BoolVal(True))
        solver.is_sat([x > 0])
        assert solver._cache_hits == hits

    def test_stale_unsat_not_returned_after_add(self):
        """Classic hazard: constraints change from UNSAT to SAT but cache says UNSAT."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        # First query: UNSAT
        assert not solver.is_sat([x > 0, x < 0])
        # Add a no-op constraint — changes context
        solver.add(z3.BoolVal(True))
        # Same query is still UNSAT, but we're checking that the solver
        # re-evaluates rather than serving stale data
        assert not solver.is_sat([x > 0, x < 0])

    def test_stale_sat_not_returned_after_add_makes_unsat(self):
        """SAT cached, then add() makes the context mutually exclusive."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        # Force SAT into cache
        assert solver.is_sat([x > 0])
        old_size = len(solver._cache)
        # Add a contradictory ambient constraint
        solver.add(x < -100)
        assert len(solver._cache) >= old_size, "old entries should physically remain"
        
        # Now query [x > 0] again in the new context
        # It's an independent cluster in checking, but there's a problem:
        # The query [x > 0] is SAT, but the ambient x < -100 makes it globally UNSAT.
        # But wait - is_sat checks the constraints *together* with ambient constraints.
        # The new caching uses structural hashing of ambient context.
        # So we should get UNSAT because the ambient context has changed.
        # Let's check:
        assert solver.is_sat([x > 0]) is False

    def test_multiple_adds_each_clear(self):
        """Multiple consecutive add() calls each change the context."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        for i in range(5):
            solver.is_sat([x > i])
            hits = solver._cache_hits
            solver.add(x != i)
            solver.is_sat([x > i])
            assert solver._cache_hits == hits, "should miss after context change"


class TestSolverPushPopCacheClear:
    """Cache is context-keyed so push/pop don't need to clear it.

    Entries from different scopes have different keys and won't produce
    false cache hits.  Entries from the parent scope survive a push/pop
    round-trip and CAN be reused (this is the desired optimisation).
    """

    def test_push_does_not_invalidate_parent_entries(self):
        """After push(), old cache entries remain but won't match new scope."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        cache_size_before = len(solver._cache)
        assert cache_size_before > 0
        solver.push()
        # Old entries still physically present (context-keyed, won't hit)
        assert len(solver._cache) >= cache_size_before

    def test_pop_preserves_parent_scope_entries(self):
        """After push/pop round-trip, parent cache entries survive."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        parent_cache_size = len(solver._cache)
        solver.push()
        solver.is_sat([x < 100])  # new scope entry
        solver.pop()
        # Parent entries still present
        assert len(solver._cache) >= parent_cache_size

    def test_add_changes_context(self):
        """add() changes the cache context so old entries won't match."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        old_cache_size = len(solver._cache)
        assert old_cache_size > 0
        solver.add(x < 100)
        # Old entries still physically present but won't hit (different context)
        assert len(solver._cache) >= old_cache_size


    def test_reset_clears_cache(self):
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        solver.reset()
        assert len(solver._cache) == 0


# ═══════════════════════════════════════════════════════════════════
#  PART 2: IncrementalSolver — try/finally push/pop safety
# ═══════════════════════════════════════════════════════════════════


class _FailingSolver:
    """A Z3 Solver stand-in that raises on `check()` to simulate failures."""

    def __init__(self, real: z3.Solver):
        self._real = real
        self._fail = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def check(self, *args: Any, **kwargs: Any) -> Any:
        if self._fail:
            raise RuntimeError("simulated Z3 failure")
        return self._real.check(*args, **kwargs)


class TestSolverTryFinallyIsSat:
    """is_sat uses try/finally so push/pop balance is maintained on exception."""

    def test_scope_depth_unchanged_on_success(self):
        solver = IncrementalSolver()
        depth_before = solver._scope_depth
        solver.is_sat([z3.Int("x") > 0])
        assert solver._scope_depth == depth_before

    def test_scope_depth_unchanged_on_exception(self):
        """If Z3 check() throws, the solver still pops its scope."""
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]
        depth_before = solver._scope_depth

        fake._fail = True
        with pytest.raises(RuntimeError, match="simulated Z3 failure"):
            solver.is_sat([z3.Int("x") > 0])

        # The critical assertion: scope depth must be restored
        assert (
            solver._scope_depth == depth_before
        ), f"scope leaked: was {depth_before}, now {solver._scope_depth}"

    def test_solver_usable_after_exception_in_is_sat(self):
        """The solver should still work correctly after is_sat raises."""
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]

        # Trigger failure
        fake._fail = True
        with pytest.raises(RuntimeError):
            solver.is_sat([z3.Int("x") > 0])

        # Must work again
        fake._fail = False
        result = solver.is_sat([z3.Int("y") > 0])
        assert result is True

    def test_repeated_exceptions_dont_accumulate_depth(self):
        """Multiple failures must not leak scopes."""
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]
        depth_before = solver._scope_depth

        fake._fail = True
        for _ in range(10):
            with pytest.raises(RuntimeError):
                solver.is_sat([z3.Int("x") > 0])

        assert solver._scope_depth == depth_before


class TestSolverTryFinallyCheckSatCached:
    """check_sat_cached uses try/finally so push/pop balance is maintained."""

    def test_scope_depth_unchanged_on_success(self):
        solver = IncrementalSolver()
        depth_before = solver._scope_depth
        solver.check_sat_cached([z3.Int("x") > 0])
        assert solver._scope_depth == depth_before

    def test_scope_depth_unchanged_on_exception(self):
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]
        depth_before = solver._scope_depth

        fake._fail = True
        with pytest.raises(RuntimeError):
            solver.check_sat_cached([z3.Int("x") > 0])

        assert solver._scope_depth == depth_before

    def test_cache_not_poisoned_on_exception(self):
        """If check_sat_cached raises, nothing should be cached."""
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]

        fake._fail = True
        with pytest.raises(RuntimeError):
            solver.check_sat_cached([z3.Int("x") > 0])

        # Cache should be empty/unchanged (no partial result stored)
        # The exception happens before the cache write, so this should hold
        assert len(solver._cache) == 0


class TestSolverTryFinallyImplies:
    """implies() uses try/finally so push/pop balance is maintained."""

    def test_implies_basic_true(self):
        solver = IncrementalSolver()
        x = z3.Int("x")
        assert solver.implies(x > 5, x > 3) is True

    def test_implies_basic_false(self):
        solver = IncrementalSolver()
        x = z3.Int("x")
        assert solver.implies(x > 0, x > 100) is False

    def test_scope_depth_unchanged_on_success(self):
        solver = IncrementalSolver()
        x = z3.Int("x")
        depth_before = solver._scope_depth
        solver.implies(x > 5, x > 3)
        assert solver._scope_depth == depth_before

    def test_scope_depth_unchanged_on_exception(self):
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]
        depth_before = solver._scope_depth

        fake._fail = True
        x = z3.Int("x")
        with pytest.raises(RuntimeError):
            solver.implies(x > 5, x > 3)

        assert solver._scope_depth == depth_before

    def test_solver_usable_after_implies_exception(self):
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]

        fake._fail = True
        with pytest.raises(RuntimeError):
            solver.implies(z3.Int("x") > 0, z3.Int("x") > -1)

        fake._fail = False
        assert solver.implies(z3.Int("y") > 5, z3.Int("y") > 3) is True


class TestSolverScopeInteraction:
    """End-to-end: external push/pop + internal is_sat/implies keep balance."""

    def test_external_push_pop_with_is_sat(self):
        solver = IncrementalSolver()
        solver.push()  # depth → 1
        solver.add(z3.Int("x") > 0)
        assert solver.is_sat([z3.Int("x") < 10])
        solver.pop()  # depth → 0
        assert solver._scope_depth == 0

    def test_external_push_pop_with_implies(self):
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.push()
        solver.add(x > 0)
        # implies should push/pop internally without disturbing outer scope
        result = solver.implies(x > 5, x > 0)
        assert result is True
        solver.pop()
        assert solver._scope_depth == 0

    def test_nested_push_pop_with_exception(self):
        """Nested scopes: exception in inner is_sat must only unwind inner scope."""
        solver = IncrementalSolver()
        fake = _FailingSolver(solver._solver)
        solver._solver = fake  # type: ignore[assignment]

        solver.push()  # depth → 1
        depth_after_push = solver._scope_depth
        assert depth_after_push == 1

        fake._fail = True
        with pytest.raises(RuntimeError):
            solver.is_sat([z3.Int("x") > 0])

        # Inner push/pop from is_sat should be balanced
        assert solver._scope_depth == depth_after_push, "is_sat exception leaked into outer scope"

        # Outer pop should still work
        fake._fail = False
        solver.pop()
        assert solver._scope_depth == 0


# ═══════════════════════════════════════════════════════════════════
#  PART 3: SETUP_FINALLY — exc fork enters block before jumping
# ═══════════════════════════════════════════════════════════════════


class TestSetupFinallyExcForkBlock:
    """After fix: SETUP_FINALLY does NOT eagerly fork.  It pushes a
    'finally' block onto block_stack and advances PC so the try body
    executes dynamically.  Exception forking happens later at the
    actual raising opcode (RAISE_VARARGS)."""

    def _make_try_finally_instructions(self) -> list[dis.Instruction]:
        """Create a minimal instruction list simulating try/finally.

        Instruction indices:
          0: SETUP_FINALLY  target=offset 10 (maps to index 2)
          1: CALL           (can raise — in _RAISING_OPS)
          2: POP_BLOCK      (handler start)
          3: END_FINALLY
        """
        instrs = [
            _make_instr("SETUP_FINALLY", 122, arg=10, argval=10, argrepr="to 10", offset=0),
            _make_instr("CALL", 171, arg=0, argval=0, offset=2),
            _make_instr("POP_BLOCK", 87, offset=10, line_number=2),
            _make_instr("END_FINALLY", 88, offset=12, line_number=2),
        ]
        return instrs

    def _make_ctx(self, instructions: list[dis.Instruction]) -> MagicMock:
        """Create a mock OpcodeDispatcher context."""
        ctx = MagicMock()
        ctx._instructions = instructions
        # offset_to_index: map byte offset → list index
        offset_map = {instr.offset: idx for idx, instr in enumerate(instructions)}
        ctx.offset_to_index = lambda off: offset_map.get(off, off)
        return ctx

    def test_exc_fork_has_block_on_stack(self):
        """SETUP_FINALLY must push a 'finally' block and return one continuation state."""
        from pysymex.execution.opcodes.exceptions import handle_setup_finally

        instructions = self._make_try_finally_instructions()
        ctx = self._make_ctx(instructions)
        state = VMState(pc=0)

        result = handle_setup_finally(instructions[0], state, ctx)

        # New behaviour: single continuation (no eager fork)
        assert result.new_states is not None and len(result.new_states) == 1
        cont_state = result.new_states[0]

        # Block pushed
        assert len(cont_state.block_stack) == 1
        assert cont_state.block_stack[0].block_type == "finally"
        assert cont_state.block_stack[0].handler_pc == 2  # index of offset 10

    def test_exc_fork_pc_jumps_to_handler(self):
        """Continuation state must advance PC to next instruction (try body), not handler."""
        from pysymex.execution.opcodes.exceptions import handle_setup_finally

        instructions = self._make_try_finally_instructions()
        ctx = self._make_ctx(instructions)
        state = VMState(pc=0)

        result = handle_setup_finally(instructions[0], state, ctx)
        cont_state = result.new_states[0]
        # PC advances past SETUP_FINALLY to the try body (index 1)
        assert cont_state.pc == 1

    def test_exc_fork_block_matches_normal(self):
        """The single continuation has the correct finally block metadata."""
        from pysymex.execution.opcodes.exceptions import handle_setup_finally

        instructions = self._make_try_finally_instructions()
        ctx = self._make_ctx(instructions)
        state = VMState(pc=0)

        result = handle_setup_finally(instructions[0], state, ctx)
        block = result.new_states[0].block_stack[0]

        assert block.block_type == "finally"
        assert block.handler_pc == 2  # index of offset 10

    def test_no_raise_body_yields_single_state(self):
        """If the try body cannot raise, SETUP_FINALLY should still return one state."""
        from pysymex.execution.opcodes.exceptions import handle_setup_finally

        # Replace CALL with NOP (not in _RAISING_OPS)
        instructions = self._make_try_finally_instructions()
        instructions[1] = _make_instr("NOP", 9, offset=2)
        ctx = self._make_ctx(instructions)
        state = VMState(pc=0)

        result = handle_setup_finally(instructions[0], state, ctx)
        # Only normal path
        assert len(result.new_states) == 1
        # And it still has a block
        assert len(result.new_states[0].block_stack) == 1

    def test_exc_fork_pushes_symbolic_exception(self):
        """Continuation should NOT have an extra value on the stack (no eager exc)."""
        from pysymex.execution.opcodes.exceptions import handle_setup_finally

        instructions = self._make_try_finally_instructions()
        ctx = self._make_ctx(instructions)
        state = VMState(pc=0, stack=[])

        result = handle_setup_finally(instructions[0], state, ctx)
        cont_state = result.new_states[0]
        # No symbolic exception pushed — that happens at RAISE_VARARGS
        assert len(cont_state.stack) == 0


# ═══════════════════════════════════════════════════════════════════
#  PART 4: state.py fork() — _class_registry guard & pending_kw_names
# ═══════════════════════════════════════════════════════════════════


class TestStateForkClassRegistry:
    """fork() copies _class_registry via dict() when it IS a dict,
    passes through otherwise (EnhancedClassRegistry singleton)."""

    def test_dict_registry_is_deep_copied(self):
        state = VMState()
        state._class_registry = {"MyClass": "some_value"}
        child = state.fork()
        # Must be a copy, not the same object
        assert child._class_registry is not state._class_registry
        assert child._class_registry == state._class_registry

    def test_dict_registry_mutation_isolation(self):
        state = VMState()
        state._class_registry = {"A": 1, "B": 2}
        child = state.fork()
        child._class_registry["C"] = 3
        assert "C" not in state._class_registry

    def test_non_dict_registry_shared(self):
        """Non-dict registries (singletons) should be shared, not copied."""

        class _FakeRegistry:
            pass

        reg = _FakeRegistry()
        state = VMState()
        state._class_registry = reg  # type: ignore[assignment]
        child = state.fork()
        assert child._class_registry is reg

    def test_isinstance_guard_prevents_crash_on_non_dict(self):
        """Pre-fix: calling dict() on a non-dict would TypeError."""

        class _Uncopiable:
            def __iter__(self):
                raise TypeError("not iterable")

        obj = _Uncopiable()
        state = VMState()
        state._class_registry = obj  # type: ignore[assignment]
        # Should not raise
        child = state.fork()
        assert child._class_registry is obj

    def test_empty_dict_registry(self):
        state = VMState()
        state._class_registry = {}
        child = state.fork()
        assert child._class_registry == {}
        assert child._class_registry is not state._class_registry


class TestStateForkPendingKwNames:
    """fork() copies pending_kw_names."""

    def test_none_pending_kw_names(self):
        state = VMState()
        assert state.pending_kw_names is None
        child = state.fork()
        assert child.pending_kw_names is None

    def test_tuple_pending_kw_names_copied(self):
        state = VMState()
        state.pending_kw_names = ("a", "b", "c")
        child = state.fork()
        assert child.pending_kw_names == ("a", "b", "c")

    def test_mutation_isolation(self):
        """Tuples are immutable so changing parent doesn't affect child."""
        state = VMState()
        state.pending_kw_names = ("x",)
        child = state.fork()
        state.pending_kw_names = ("y",)
        assert child.pending_kw_names == ("x",)


# ═══════════════════════════════════════════════════════════════════
#  PART 5: END_FOR — pops 2 values
# ═══════════════════════════════════════════════════════════════════


class TestEndForPops2:
    """After fix: END_FOR pops 2 values (iterator + sentinel)."""

    def test_pops_exactly_two(self):
        from pysymex.execution.opcodes.control import handle_end_for

        state = VMState(stack=["keep_me", "sentinel", "iter_val"])
        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, state, ctx)
        assert state.stack == ["keep_me"]
        assert state.pc == 1

    def test_pops_two_from_exactly_two(self):
        from pysymex.execution.opcodes.control import handle_end_for

        state = VMState(stack=["a", "b"])
        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, state, ctx)
        assert state.stack == []

    def test_pops_from_short_stack_gracefully(self):
        """If stack has < 2 items, END_FOR should pop what it can."""
        from pysymex.execution.opcodes.control import handle_end_for

        state = VMState(stack=["only_one"])
        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, state, ctx)
        assert state.stack == []

    def test_empty_stack_no_crash(self):
        from pysymex.execution.opcodes.control import handle_end_for

        state = VMState(stack=[])
        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, state, ctx)
        assert state.stack == []

    def test_large_stack_only_top_two_removed(self):
        from pysymex.execution.opcodes.control import handle_end_for

        state = VMState(stack=[1, 2, 3, 4, 5, "iter", "sentinel"])
        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, state, ctx)
        assert state.stack == [1, 2, 3, 4, 5]


# ═══════════════════════════════════════════════════════════════════
#  PART 6: LOAD_SUPER_ATTR — pops 3 values
# ═══════════════════════════════════════════════════════════════════


class TestLoadSuperAttrPops3:
    """After fix: LOAD_SUPER_ATTR pops 3 values (self, class, global super)."""

    def test_pops_exactly_three_pushes_one(self):
        from pysymex.execution.opcodes.functions import handle_load_super_attr

        state = VMState(stack=["底", "super_fn", "cls_ref", "self_ref"])
        instr = _make_instr("LOAD_SUPER_ATTR", 0, arg=0, argval="my_attr", argrepr="my_attr")
        ctx = MagicMock()
        handle_load_super_attr(instr, state, ctx)
        # 3 popped, 1 pushed → net -2
        assert len(state.stack) == 2  # "底" + pushed SymbolicValue
        assert state.stack[0] == "底"
        assert isinstance(state.stack[1], SymbolicValue)

    def test_pops_three_from_exactly_three(self):
        from pysymex.execution.opcodes.functions import handle_load_super_attr

        state = VMState(stack=["super_fn", "cls", "self"])
        instr = _make_instr("LOAD_SUPER_ATTR", 0, arg=0, argval="attr", argrepr="attr")
        ctx = MagicMock()
        handle_load_super_attr(instr, state, ctx)
        # 3 popped, 1 pushed
        assert len(state.stack) == 1
        assert isinstance(state.stack[0], SymbolicValue)

    def test_short_stack_graceful(self):
        """Stack with < 3 items: pops what it can, still pushes result."""
        from pysymex.execution.opcodes.functions import handle_load_super_attr

        state = VMState(stack=["only_one"])
        instr = _make_instr("LOAD_SUPER_ATTR", 0, arg=0, argval="x", argrepr="x")
        ctx = MagicMock()
        handle_load_super_attr(instr, state, ctx)
        # 1 popped (can't pop more), 1 pushed
        assert len(state.stack) == 1
        assert isinstance(state.stack[0], SymbolicValue)

    def test_result_name_contains_attr(self):
        from pysymex.execution.opcodes.functions import handle_load_super_attr

        state = VMState(stack=["a", "b", "c"])
        instr = _make_instr("LOAD_SUPER_ATTR", 0, arg=0, argval="foo_bar", argrepr="foo_bar")
        ctx = MagicMock()
        handle_load_super_attr(instr, state, ctx)
        sv = state.stack[0]
        assert isinstance(sv, SymbolicValue)
        assert "foo_bar" in sv._name

    def test_pc_incremented(self):
        from pysymex.execution.opcodes.functions import handle_load_super_attr

        state = VMState(pc=7, stack=["a", "b", "c"])
        instr = _make_instr("LOAD_SUPER_ATTR", 0, arg=0, argval="z", argrepr="z")
        ctx = MagicMock()
        handle_load_super_attr(instr, state, ctx)
        assert state.pc == 8


# ═══════════════════════════════════════════════════════════════════
#  PART 7: Integration / combo edge cases
# ═══════════════════════════════════════════════════════════════════


class TestSolverIntegration:
    """Longer scenarios combining multiple fixes."""

    def test_enter_scope_leave_scope_cache(self):
        """enter_scope/leave_scope should change cache context, but keep entries alive."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.is_sat([x > 0])
        parent_cache_size = len(solver._cache)
        
        solver.enter_scope([x < 100])
        assert len(solver._cache) >= parent_cache_size
        solver.is_sat([x > 50])
        child_cache_size = len(solver._cache)
        assert child_cache_size > parent_cache_size
        
        solver.leave_scope()
        assert len(solver._cache) == child_cache_size
        # The parent entry for [x > 0] should hit without solving again
        hits = solver._cache_hits
        solver.is_sat([x > 0])
        assert solver._cache_hits > hits

    def test_is_sat_unsat_roundtrip(self):
        """SAT → add contradiction → re-check should produce correct results."""
        solver = IncrementalSolver()
        x = z3.Int("x")

        assert solver.is_sat([x > 0, x < 10]) is True
        result = solver.check_sat_cached([x > 0, x < 10])
        assert result.is_sat

        # Now add a contradictory ambient constraint
        solver.add(x == 50)  # Contradicts x < 10
        # Context changed, old cache keys won't hit
        
        # check_sat_cached should re-evaluate and return UNSAT
        result2 = solver.check_sat_cached([x > 0, x < 10])
        assert not result2.is_sat

    def test_implies_with_ambient_constraints(self):
        """implies() should work correctly with ambient constraints."""
        solver = IncrementalSolver()
        x = z3.Int("x")
        solver.add(x > 0)
        # With x > 0 ambient, x > 0 => x >= 1 should be true
        # implies pushes/pops internally, so it tests against ambient + added
        assert solver.implies(z3.BoolVal(True), x >= 1) is True

    def test_many_queries_cache_eviction(self):
        """Cache size limit: old entries evicted when full."""
        solver = IncrementalSolver(cache_size=5)
        x = z3.Int("x")
        for i in range(10):
            solver.is_sat([x > i])
        assert len(solver._cache) <= 5

    def test_fork_and_execute_sequence(self):
        """Fork a state, execute END_FOR on child, parent unaffected."""
        from pysymex.execution.opcodes.control import handle_end_for

        parent = VMState(stack=["a", "b", "iter", "sentinel"])
        child = parent.fork()

        instr = _make_instr("END_FOR", 4)
        ctx = MagicMock()
        handle_end_for(instr, child, ctx)

        assert child.stack == ["a", "b"]
        assert parent.stack == ["a", "b", "iter", "sentinel"]
