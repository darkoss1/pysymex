"""Shared fixtures for data-flow analysis tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis

if TYPE_CHECKING:
    from collections.abc import Iterable


class MockInstr:
    """Minimal instruction stub satisfying the attrs BasicBlock expects."""

    def __init__(self, opname: str, offset: int, argval: object = None, argrepr: str = "") -> None:
        self.opname = opname
        self.offset = offset
        self.argval = argval
        self.argrepr = argrepr
        self.starts_line: int | None = 10
        self.positions: object = None


def make_block(
    block_id: int,
    instrs: list[MockInstr] | None = None,
    *,
    successors: set[int] | None = None,
    predecessors: set[int] | None = None,
) -> BasicBlock:
    """Create a BasicBlock with mock instructions."""
    bb = BasicBlock(id=block_id, start_pc=0, end_pc=0)
    if instrs is not None:
        object.__setattr__(bb, "instructions", instrs)  # type: ignore[assignment]
    if successors is not None:
        bb.successors = successors
    if predecessors is not None:
        bb.predecessors = predecessors
    return bb


class MockCFG(ControlFlowGraph):
    """Minimal CFG stub for unit tests."""

    def __init__(self) -> None:
        super().__init__()
        self.entry_block_id = 0
        self.exit_block_ids = {1}

    def iter_blocks_forward(self) -> Iterable[BasicBlock]:
        """Iterate blocks in insertion order."""
        return [self.blocks[k] for k in sorted(self.blocks.keys())]

    def iter_blocks_reverse(self) -> Iterable[BasicBlock]:
        """Iterate blocks in reverse insertion order."""
        return [self.blocks[k] for k in sorted(self.blocks.keys(), reverse=True)]

    def get_block_at_pc(self, pc: int) -> BasicBlock | None:
        """Return the first block, if any."""
        if self.blocks:
            return next(iter(self.blocks.values()))
        return None


class ConcreteDataFlow(DataFlowAnalysis[str]):
    """Concrete data-flow analysis for testing the abstract base class."""

    def initial_value(self) -> str:
        """Return the initial data-flow value."""
        return "init"

    def boundary_value(self) -> str:
        """Return the boundary data-flow value."""
        return "bound"

    def transfer(self, block: BasicBlock, in_fact: str) -> str:
        """Apply the transfer function."""
        return in_fact + "_" + str(block.id)

    def meet(self, facts: list[str]) -> str:
        """Compute the meet of data-flow facts."""
        return "+".join(sorted(facts)) if facts else "init"


__all__ = ["ConcreteDataFlow", "MockCFG", "MockInstr", "make_block"]
