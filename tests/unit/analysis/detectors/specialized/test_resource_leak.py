"""Tests for pysymex/analysis/detectors/specialized/resource_leak.py."""

from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex._typing import StackValue
from pysymex.analysis.detectors.specialized.resource_leak import (
    ResourceLeakDetector,
    get_named_value_name,
    resolve_target_name,
)
from pysymex.core.state import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


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


class _CloseTarget:
    """Callable-like object exposing close target name metadata."""

    __name__ = "close"

    def __call__(self) -> None:
        return None


class TestResourceLeakDetector:
    """Test suite for specialized resource leak detector behavior."""

    def test_check_tracks_open_and_reports_on_return(self) -> None:
        """Report RESOURCE_LEAK when opened resources are not closed before returning."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=0, argval=0)
        return_instr = _make_instruction("RETURN_VALUE")
        state = VMState(stack=[open], path_constraints=[], pc=1)

        # Simulating opening a resource
        detector.check(state, call_open, _always_sat)

        # Simulating returning before closing
        issue = detector.check(state, return_instr, _always_sat)

        assert issue is not None
        assert issue.kind.name == "RESOURCE_LEAK"

    def test_check_maintains_path_local_open_count_on_fork(self) -> None:
        """Keep open resource counters isolated across forked execution paths."""
        detector = ResourceLeakDetector()
        call_open = _make_instruction("CALL", arg=0, argval=0)
        call_close = _make_instruction("CALL", arg=0, argval=0)

        state_left = VMState(stack=[open], path_constraints=[], pc=1)
        detector.check(state_left, call_open, _always_sat)

        state_right = state_left.fork()
        state_right.stack = [cast(StackValue, _CloseTarget())]

        detector.check(state_right, call_close, _always_sat)

        assert state_left.open_resources == 1
        assert state_right.open_resources == 0


def test_get_named_value_name_returns_protocol_name() -> None:
    """Return object name when value satisfies the simple named helper protocol."""
    value_name = get_named_value_name(_NamedValue("file_handle"))
    assert value_name == "file_handle"


def test_resolve_target_name_picks_callable_name_on_stack() -> None:
    """Resolve call target from stack shape based on argument count."""
    state = VMState(stack=[open], path_constraints=[], pc=0)
    target = resolve_target_name(state, argc=0)
    assert target == "open"
