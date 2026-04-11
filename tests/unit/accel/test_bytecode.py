import pytest
import z3

from pysymex.accel.bytecode import (
    BytecodeCompiler,
    CompiledConstraint,
    INSTRUCTION_DTYPE,
    Instruction,
    MAX_VARIABLES,
    Opcode,
    compile_constraint,
    disassemble,
)


class TestOpcode:
    def test_initialization(self) -> None:
        assert int(Opcode.NOP) == 0x00
        assert int(Opcode.HALT) == 0xFF
        assert int(Opcode.AND) == 0x10


class TestInstruction:
    def test_to_tuple(self) -> None:
        instr = Instruction(Opcode.LOAD_VAR, dst=2, immediate=1)
        encoded = instr.to_tuple()
        assert encoded[0] == int(Opcode.LOAD_VAR)
        assert encoded[1] == 2
        assert encoded[5] == 1


class TestCompiledConstraint:
    @staticmethod
    def _constraint() -> CompiledConstraint:
        x, y = z3.Bools("x y")
        return compile_constraint(z3.And(x, y), ["x", "y"])

    def test_instruction_count(self) -> None:
        c = self._constraint()
        assert c.instruction_count >= 2

    def test_num_states(self) -> None:
        c = self._constraint()
        assert c.num_states == 4

    def test_output_bitmap_size(self) -> None:
        c = self._constraint()
        assert c.output_bitmap_size == 1

    def test_memory_bytes(self) -> None:
        c = self._constraint()
        assert c.memory_bytes() == int(c.instructions.nbytes) + c.output_bitmap_size


class TestBytecodeCompiler:
    def test_compile(self) -> None:
        compiler = BytecodeCompiler()
        x, y = z3.Bools("x y")
        c = compiler.compile(z3.Or(x, y), ["x", "y"])

        assert c.instructions.dtype == INSTRUCTION_DTYPE
        assert c.num_variables == 2
        assert c.register_count >= 3
        assert int(c.instructions[-1]["opcode"]) == int(Opcode.HALT)

    def test_compile_rejects_empty_variable_list(self) -> None:
        compiler = BytecodeCompiler()
        x = z3.Bool("x")
        with pytest.raises(ValueError, match="At least one variable required"):
            compiler.compile(x, [])

    def test_compile_rejects_too_many_variables(self) -> None:
        compiler = BytecodeCompiler()
        var_names = [f"v{i}" for i in range(MAX_VARIABLES + 1)]
        expr = z3.And(*[z3.Bool(v) for v in var_names])
        with pytest.raises(ValueError, match="Too many variables"):
            compiler.compile(expr, var_names)


def test_compile_constraint_caches_by_structure_and_variable_order() -> None:
    x, y = z3.Bools("x y")
    c1 = compile_constraint(z3.And(x, y), ["x", "y"])
    c2 = compile_constraint(z3.And(x, y), ["x", "y"])
    assert c1 is c2


def test_disassemble_contains_instruction_summary_and_halt() -> None:
    x = z3.Bool("x")
    c = compile_constraint(x, ["x"])
    asm = disassemble(c)
    assert "CompiledConstraint" in asm
    assert "HALT" in asm
