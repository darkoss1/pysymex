import z3
import pytest

from pysymex.accel.bytecode import Opcode, compile_constraint
from pysymex.accel.optimizer import (
    OptInstruction,
    OptimizationStats,
    clear_cache,
    optimize,
)


class TestOptimizationStats:
    def test_reduction_percent(self) -> None:
        stats = OptimizationStats(original_instructions=10, optimized_instructions=7)
        assert stats.reduction_percent == pytest.approx(30.0)


class TestOptInstruction:
    def test_from_numpy(self) -> None:
        x = z3.Bool("x")
        compiled = compile_constraint(x, ["x"])
        instr = OptInstruction.from_numpy(compiled.instructions[0])
        assert isinstance(instr.opcode, Opcode)

    def test_to_tuple(self) -> None:
        instr = OptInstruction(opcode=Opcode.AND, dst=5, src1=3, src2=4)
        encoded = instr.to_tuple()
        assert encoded[0] == int(Opcode.AND)
        assert encoded[1:4] == (5, 3, 4)

    def test_writes(self) -> None:
        assert OptInstruction(opcode=Opcode.NOP, dst=4).writes() is None
        assert OptInstruction(opcode=Opcode.AND, dst=4).writes() == 4

    def test_reads(self) -> None:
        assert OptInstruction(opcode=Opcode.LOAD_VAR, immediate=1).reads() == []
        assert OptInstruction(opcode=Opcode.COPY, src1=3).reads() == [3]
        assert OptInstruction(opcode=Opcode.ITE, src1=1, src2=2, immediate=3).reads() == [1, 2, 3]

    def test_canonical_key(self) -> None:
        and_a = OptInstruction(opcode=Opcode.AND, src1=4, src2=2)
        and_b = OptInstruction(opcode=Opcode.AND, src1=2, src2=4)
        assert and_a.canonical_key() == and_b.canonical_key()


def test_optimize_reduces_or_preserves_instruction_count_and_keeps_halt() -> None:
    x, y = z3.Bools("x y")
    compiled = compile_constraint(z3.And(x, x, y, z3.BoolVal(True)), ["x", "y"])
    optimized, stats = optimize(compiled)

    assert optimized.instruction_count <= compiled.instruction_count
    assert int(optimized.instructions[-1]["opcode"]) == int(Opcode.HALT)
    assert stats.original_instructions == compiled.instruction_count
    assert stats.optimized_instructions == optimized.instruction_count


def test_clear_cache_is_safe_and_idempotent() -> None:
    clear_cache()
    clear_cache()
