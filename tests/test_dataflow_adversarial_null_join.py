"""Adversarial soundness tests for dataflow null-state joins."""

from __future__ import annotations

import dis
import inspect

from pysymex.analysis.dataflow.types import NullInfo, NullState
from pysymex.analysis.cfg import BasicBlock, ControlFlowGraph
from pysymex.analysis.dataflow.core import DefUseAnalysis, LiveVariables, ReachingDefinitions


def test_null_join_unknown_path_must_not_collapse_to_definitely_not_null() -> None:
    """Joining UNKNOWN with DEFINITELY_NOT_NULL must preserve uncertainty.

    Adversarial shape:
    - Path A establishes `x` as definitely not null.
    - Path B provides no fact for `x` (state is UNKNOWN).

    A sound join cannot return DEFINITELY_NOT_NULL, because Path B may carry
    `x is None` at runtime. Returning DEFINITELY_NOT_NULL would let downstream
    checks skip potential None-dereference reports.
    """

    path_a = NullInfo(states={"x": NullState.DEFINITELY_NOT_NULL})
    path_b = NullInfo(states={})

    joined = path_a.join(path_b)

    assert joined.get_state("x") in {NullState.UNKNOWN, NullState.MAYBE_NULL}


def _make_instr(opname: str, opcode: int, argval: str, offset: int, line: int) -> dis.Instruction:
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


def test_reaching_defs_delete_fast_kills_definition() -> None:
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
    cfg.dominators[0] = {0}
    for pc in range(0, 5):
        cfg.pc_to_block[pc] = 0

    rd = ReachingDefinitions(cfg)
    rd.analyze()

    reaching = rd.get_reaching_defs_at(4)
    x_defs = {d for d in reaching if d.var_name == "x"}
    assert len(x_defs) == 0


def _single_block_cfg(instructions: list[dis.Instruction], end_pc: int) -> ControlFlowGraph:
    block = BasicBlock(id=0, start_pc=0, end_pc=end_pc)
    block.instructions = instructions
    cfg = ControlFlowGraph()
    cfg.blocks[0] = block
    cfg.entry_block_id = 0
    cfg.exit_block_ids = {0}
    cfg.dominators[0] = {0}
    for pc in range(0, end_pc + 1):
        cfg.pc_to_block[pc] = 0
    return cfg


def test_reaching_defs_delete_name_kills_definition() -> None:
    cfg = _single_block_cfg(
        [
            _make_instr("STORE_NAME", 90, "x", 0, 1),
            _make_instr("DELETE_NAME", 91, "x", 2, 2),
            _make_instr("LOAD_NAME", 101, "x", 4, 3),
        ],
        end_pc=4,
    )
    rd = ReachingDefinitions(cfg)
    rd.analyze()
    reaching = rd.get_reaching_defs_at(4)
    assert {d for d in reaching if d.var_name == "x"} == set()


def test_live_variables_delete_fast_kills_liveness() -> None:
    cfg = _single_block_cfg(
        [
            _make_instr("LOAD_FAST", 124, "x", 0, 1),
            _make_instr("DELETE_FAST", 126, "x", 2, 2),
        ],
        end_pc=2,
    )
    lv = LiveVariables(cfg)
    lv.analyze()
    # At/after DELETE_FAST, x should not remain live in the same block transfer semantics.
    assert lv.is_live_at("x", 2) is False


def test_def_use_chain_drops_uses_after_delete() -> None:
    cfg = _single_block_cfg(
        [
            _make_instr("STORE_FAST", 125, "x", 0, 1),
            _make_instr("DELETE_FAST", 126, "x", 2, 2),
            _make_instr("LOAD_FAST", 124, "x", 4, 3),
        ],
        end_pc=4,
    )
    du = DefUseAnalysis(cfg)
    x_defs = [d for d in du.chains if d.var_name == "x"]
    assert x_defs
    # The deleted definition must not have a reaching use at pc=4.
    assert all(len(du.chains[d].uses) == 0 for d in x_defs)
