"""Tests for pysymex/analysis/detectors/specialized/use_after_free.py."""

from __future__ import annotations

import dis

import z3

from pysymex._typing import StackValue
from pysymex.analysis.detectors.specialized.use_after_free import UseAfterFreeDetector
from pysymex.core.state import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _stack(*values: StackValue) -> list[StackValue]:
    return list(values)


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic bytecode instructions for detector tests."""

    def _dummy() -> None:
        """Provide a stable instruction template."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class _NamedValue:
    """Simple object that exposes a public detector-friendly name."""

    def __init__(self, name: str) -> None:
        self.name = name

    def __call__(self) -> object:
        return None


class TestUseAfterFreeDetector:
    """Test suite for specialized UseAfterFreeDetector behavior."""

    def test_check_records_closed_resource_on_call(self) -> None:
        """Record the object name in freed_vars when its .close() method is called."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL", arg=0)
        # target_name would be "f.close", receiver name would be "f"
        # We need stack setup: [receiver, method_function]
        # Wait, for CALL, argc=0.
        # Stack should have receiver at -(argc + 2) if it was a method call.
        # Let's provide a named value at the receiver slot.
        # Python 3.11+ CALL: stack has [callable, self/null, arg1...]
        receiver = _NamedValue("my_file")

        def close_fn() -> None:
            pass

        close_fn.__name__ = "my_file.close"

        state = VMState(stack=_stack(receiver, close_fn), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" in state.freed_vars

    def test_check_records_closed_resource_when_callable_precedes_receiver(self) -> None:
        """Record receiver name for CALL stack shape [callable, receiver]."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL", arg=0)
        receiver = _NamedValue("my_file")

        class _CloseCallable:
            __name__ = "my_file.close"

            def __call__(self) -> object:
                return None

        state = VMState(stack=_stack(_CloseCallable(), receiver), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" in state.freed_vars

    def test_check_ignores_non_close_method_call(self) -> None:
        """Do not record object names in freed_vars if the method is not .close()."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL", arg=0)
        receiver = _NamedValue("my_file")

        def read_fn() -> None:
            pass

        read_fn.__name__ = "my_file.read"

        state = VMState(stack=_stack(receiver, read_fn), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" not in state.freed_vars

    def test_check_ignores_call_with_insufficient_stack(self) -> None:
        """Do not record any closures if the stack is shorter than expected."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL", arg=0)

        def close_fn() -> None:
            pass

        close_fn.__name__ = "my_file.close"

        # Only 1 element on stack (the callable), no receiver present
        state = VMState(stack=_stack(close_fn), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" not in state.freed_vars

    def test_check_reports_issue_when_loading_freed_resource(self) -> None:
        """Report ATTRIBUTE_ERROR when accessing an attribute/method of a freed resource."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("LOAD_METHOD")
        receiver = _NamedValue("my_file")

        state = VMState(stack=_stack(receiver), path_constraints=[], pc=1)
        state.freed_vars.add("my_file")

        issue = detector.check(state, instruction, _always_sat)

        assert issue is not None
        assert issue.kind.name == "ATTRIBUTE_ERROR"

    def test_check_returns_none_when_loading_active_resource(self) -> None:
        """Return None when accessing an attribute/method of a valid active resource."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("LOAD_METHOD")
        receiver = _NamedValue("my_file")

        state = VMState(stack=_stack(receiver), path_constraints=[], pc=1)
        # my_file is not in freed_vars

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_returns_none_for_load_with_empty_stack(self) -> None:
        """Return None when processing a LOAD instruction with an empty stack."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("LOAD_METHOD")

        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_ignores_unrelated_opcode(self) -> None:
        """Return None when processing opcodes not related to resource lifecycle."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("LOAD_CONST")
        receiver = _NamedValue("my_file")

        state = VMState(stack=_stack(receiver), path_constraints=[], pc=1)
        state.freed_vars.add("my_file")

        issue = detector.check(state, instruction, _always_sat)

        assert issue is None

    def test_check_records_closed_resource_on_call_method(self) -> None:
        """Record freed resource names when CALL_METHOD invokes a .close target."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL_METHOD", arg=0)
        receiver = _NamedValue("my_file")

        class _CloseCallable:
            __name__ = "my_file.close"

            def __call__(self) -> object:
                return None

        state = VMState(stack=_stack(receiver, _CloseCallable()), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" in state.freed_vars

    def test_check_records_closed_resource_on_call_kw(self) -> None:
        """Record freed resource names when CALL_KW invokes a .close target."""
        detector = UseAfterFreeDetector()
        instruction = _make_instruction("CALL_KW", arg=0)
        receiver = _NamedValue("my_file")

        class _CloseCallable:
            __name__ = "my_file.close"

            def __call__(self) -> object:
                return None

        state = VMState(stack=_stack(receiver, _CloseCallable()), path_constraints=[], pc=1)
        detector.check(state, instruction, _always_sat)

        assert "my_file" in state.freed_vars
