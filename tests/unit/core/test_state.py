import z3

from pysymex.core.state.factory import create_initial_state
from pysymex.core.state.record import VMState
from pysymex.core.state.types import UNBOUND, BlockInfo, CallFrame, wrap_cow_dict, wrap_cow_set
from pysymex.core.types.scalars.values import SymbolicValue


class TestHashableValue:
    def test_hash_value(self) -> None:
        block = BlockInfo("loop", 0, 1)
        assert isinstance(block.hash_value(), int)


def test_wrap_cow_dict() -> None:
    wrapped = wrap_cow_dict({"x": SymbolicValue.from_const(1)})
    assert "x" in wrapped


def test_wrap_cow_set() -> None:
    wrapped = wrap_cow_set({1, 2})
    assert 1 in wrapped


class TestBlockInfo:
    def test_hash_value(self) -> None:
        block = BlockInfo("try", 1, 3)
        assert isinstance(block.hash_value(), int)


class TestCallFrame:
    def test_hash_value(self) -> None:
        frame = CallFrame("f", 1, wrap_cow_dict({}), 0)
        assert isinstance(frame.hash_value(), int)


class TestVMState:
    def test_push(self) -> None:
        state = VMState().push(SymbolicValue.from_const(1))
        assert len(state.stack) == 1

    def test_pop(self) -> None:
        state = VMState().push(SymbolicValue.from_const(1))
        assert state.pop() is not None

    def test_peek(self) -> None:
        state = VMState().push(SymbolicValue.from_const(1))
        assert state.peek() is not None

    def test_advance_pc(self) -> None:
        state = VMState().advance_pc(2)
        assert state.pc == 2

    def test_set_pc(self) -> None:
        state = VMState().set_pc(9)
        assert state.pc == 9

    def test_set_local(self) -> None:
        state = VMState().set_local("x", SymbolicValue.from_const(1))
        assert state.get_local("x") is not UNBOUND

    def test_set_global(self) -> None:
        state = VMState().set_global("g", SymbolicValue.from_const(2))
        assert state.get_global("g") is not None

    def test_add_constraint(self) -> None:
        state = VMState().add_constraint(z3.Bool("c"))
        assert len(state.path_constraints) == 1

    def test_false_constraint_requires_feasibility_check(self) -> None:
        state = VMState().add_constraint(z3.BoolVal(False))
        assert state.pending_constraint_count == 1

    def test_record_branch(self) -> None:
        state = VMState().record_branch(z3.Bool("c"), True, 1)
        assert len(state.branch_trace) == 1

    def test_mark_visited(self) -> None:
        state = VMState(pc=5)
        assert not state.mark_visited()

    def test_enter_block(self) -> None:
        state = VMState().enter_block(BlockInfo("loop", 0, 2))
        assert state.current_block() is not None

    def test_exit_block(self) -> None:
        state = VMState().enter_block(BlockInfo("loop", 0, 2))
        assert state.exit_block() is not None

    def test_push_call(self) -> None:
        frame = CallFrame("f", 1, wrap_cow_dict({}), 0)
        state = VMState().push_call(frame)
        assert state.call_depth() == 1

    def test_pop_call(self) -> None:
        frame = CallFrame("f", 1, wrap_cow_dict({}), 0)
        state = VMState().push_call(frame)
        assert state.pop_call() is frame

    def test_get_local(self) -> None:
        state = VMState().set_local("x", SymbolicValue.from_const(1))
        assert state.get_local("x") is not UNBOUND

    def test_get_global(self) -> None:
        state = VMState().set_global("x", SymbolicValue.from_const(1))
        assert state.get_global("x") is not None

    def test_locals(self) -> None:
        state = VMState()
        assert state.locals is state.local_vars

    def test_current_block(self) -> None:
        state = VMState().enter_block(BlockInfo("loop", 0, 1))
        assert state.current_block() is not None

    def test_call_depth(self) -> None:
        state = VMState()
        assert state.call_depth() == 0

    def test_copy_constraints(self) -> None:
        state = VMState().add_constraint(z3.Bool("c"))
        assert len(state.copy_constraints()) == 1

    def test_constraint_hash(self) -> None:
        state = VMState().add_constraint(z3.Bool("c"))
        assert isinstance(state.constraint_hash(), int)

    def test_hash_value(self) -> None:
        assert isinstance(VMState().hash_value(), int)

    def test_hash_value_updates_after_block_stack_mutation(self) -> None:
        state = VMState()
        before = state.hash_value()

        state.enter_block(BlockInfo("loop", 0, 2))
        with_block = state.hash_value()
        state.exit_block()
        after_exit = state.hash_value()

        assert with_block != before
        assert after_exit == before

    def test_hash_value_updates_after_call_stack_mutation(self) -> None:
        state = VMState()
        frame = CallFrame("f", 1, wrap_cow_dict({}), 0)
        before = state.hash_value()

        state.push_call(frame)
        with_call = state.hash_value()
        state.pop_call()
        after_pop = state.hash_value()

        assert with_call != before
        assert after_pop == before

    def test_fork(self) -> None:
        state = VMState().set_local("x", SymbolicValue.from_const(1))
        child = state.fork()
        assert child is not state and child.get_local("x") is not UNBOUND

    def test_copy(self) -> None:
        state = VMState()
        assert state.copy() is not state

    def test_replace(self) -> None:
        state = VMState()
        replaced = state.replace(pc=10)
        assert replaced.pc == 10 and replaced is not state


def test_create_initial_state() -> None:
    state = create_initial_state()
    assert state.get_global("__name__") == "__main__"
