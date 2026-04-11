import z3

import pysymex.core.state as mod
from pysymex.core.types.scalars import SymbolicValue


class TestHashableValue:
    def test_hash_value(self) -> None:
        block = mod.BlockInfo("loop", 0, 1)
        assert isinstance(block.hash_value(), int)


def test_wrap_cow_dict() -> None:
    wrapped = mod.wrap_cow_dict({"x": SymbolicValue.from_const(1)})
    assert "x" in wrapped


def test_wrap_cow_set() -> None:
    wrapped = mod.wrap_cow_set({1, 2})
    assert 1 in wrapped


class TestBlockInfo:
    def test_hash_value(self) -> None:
        block = mod.BlockInfo("try", 1, 3)
        assert isinstance(block.hash_value(), int)


class TestCallFrame:
    def test_hash_value(self) -> None:
        frame = mod.CallFrame("f", 1, mod.wrap_cow_dict({}), 0)
        assert isinstance(frame.hash_value(), int)


class TestVMState:
    def test_pending_taint_issues(self) -> None:
        state = mod.VMState()
        assert state.pending_taint_issues == []

    def test_pending_taint_issues_assignment(self) -> None:
        state = mod.VMState()
        state.pending_taint_issues = ["issue"]
        assert state.pending_taint_issues == ["issue"]

    def test_building_class(self) -> None:
        assert not mod.VMState().building_class

    def test_building_class_assignment(self) -> None:
        state = mod.VMState()
        state.building_class = True
        assert state.building_class

    def test_class_registry(self) -> None:
        assert isinstance(mod.VMState().class_registry, dict)

    def test_class_registry_assignment(self) -> None:
        state = mod.VMState()
        state.class_registry = {"C": object()}
        assert "C" in state.class_registry

    def test_object_state(self) -> None:
        assert mod.VMState().object_state is not None

    def test_object_state_assignment(self) -> None:
        state = mod.VMState()
        obj_state = state.object_state
        state.object_state = obj_state
        assert state.object_state is obj_state

    def test_push(self) -> None:
        state = mod.VMState().push(SymbolicValue.from_const(1))
        assert len(state.stack) == 1

    def test_pop(self) -> None:
        state = mod.VMState().push(SymbolicValue.from_const(1))
        assert state.pop() is not None

    def test_peek(self) -> None:
        state = mod.VMState().push(SymbolicValue.from_const(1))
        assert state.peek() is not None

    def test_advance_pc(self) -> None:
        state = mod.VMState().advance_pc(2)
        assert state.pc == 2

    def test_set_pc(self) -> None:
        state = mod.VMState().set_pc(9)
        assert state.pc == 9

    def test_set_local(self) -> None:
        state = mod.VMState().set_local("x", SymbolicValue.from_const(1))
        assert state.get_local("x") is not mod.UNBOUND

    def test_set_global(self) -> None:
        state = mod.VMState().set_global("g", SymbolicValue.from_const(2))
        assert state.get_global("g") is not None

    def test_add_constraint(self) -> None:
        state = mod.VMState().add_constraint(z3.Bool("c"))
        assert len(state.path_constraints) == 1

    def test_record_branch(self) -> None:
        state = mod.VMState().record_branch(z3.Bool("c"), True, 1)
        assert len(state.branch_trace) == 1

    def test_mark_visited(self) -> None:
        state = mod.VMState(pc=5)
        assert not state.mark_visited()

    def test_enter_block(self) -> None:
        state = mod.VMState().enter_block(mod.BlockInfo("loop", 0, 2))
        assert state.current_block() is not None

    def test_exit_block(self) -> None:
        state = mod.VMState().enter_block(mod.BlockInfo("loop", 0, 2))
        assert state.exit_block() is not None

    def test_push_call(self) -> None:
        frame = mod.CallFrame("f", 1, mod.wrap_cow_dict({}), 0)
        state = mod.VMState().push_call(frame)
        assert state.call_depth() == 1

    def test_pop_call(self) -> None:
        frame = mod.CallFrame("f", 1, mod.wrap_cow_dict({}), 0)
        state = mod.VMState().push_call(frame)
        assert state.pop_call() is frame

    def test_get_local(self) -> None:
        state = mod.VMState().set_local("x", SymbolicValue.from_const(1))
        assert state.get_local("x") is not mod.UNBOUND

    def test_get_global(self) -> None:
        state = mod.VMState().set_global("x", SymbolicValue.from_const(1))
        assert state.get_global("x") is not None

    def test_locals(self) -> None:
        state = mod.VMState()
        assert state.locals is state.local_vars

    def test_current_block(self) -> None:
        state = mod.VMState().enter_block(mod.BlockInfo("loop", 0, 1))
        assert state.current_block() is not None

    def test_call_depth(self) -> None:
        state = mod.VMState()
        assert state.call_depth() == 0

    def test_copy_constraints(self) -> None:
        state = mod.VMState().add_constraint(z3.Bool("c"))
        assert len(state.copy_constraints()) == 1

    def test_constraint_hash(self) -> None:
        state = mod.VMState().add_constraint(z3.Bool("c"))
        assert isinstance(state.constraint_hash(), int)

    def test_hash_value(self) -> None:
        assert isinstance(mod.VMState().hash_value(), int)

    def test_fork(self) -> None:
        state = mod.VMState().set_local("x", SymbolicValue.from_const(1))
        child = state.fork()
        assert child is not state and child.get_local("x") is not mod.UNBOUND

    def test_copy(self) -> None:
        state = mod.VMState()
        assert state.copy() is not state

    def test_replace(self) -> None:
        state = mod.VMState()
        replaced = state.replace(pc=10)
        assert replaced.pc == 10 and replaced is not state


def test_create_initial_state() -> None:
    state = mod.create_initial_state()
    assert state.get_global("__name__") == "__main__"
