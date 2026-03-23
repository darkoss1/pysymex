"""
Bytecode ISA and Compiler Tests.

Validates:
1. Instruction encoding and decoding
2. Z3-to-bytecode compilation
3. Common subexpression elimination
4. Register allocation bounds
5. Disassembler output
"""

from __future__ import annotations

import pytest
import numpy as np

@pytest.fixture
def z3_module():
    """Import Z3 or skip test."""
    z3 = pytest.importorskip("z3")
    return z3

@pytest.fixture
def bytecode_module():
    """Import bytecode module."""
    from pysymex.h_acceleration import bytecode
    return bytecode

class TestInstruction:
    """Test Instruction dataclass."""

    def test_instruction_creation(self, bytecode_module):
        """Test basic instruction creation."""
        Instruction = bytecode_module.Instruction
        Opcode = bytecode_module.Opcode

        instr = Instruction(Opcode.AND, dst=5, src1=1, src2=2)
        assert instr.opcode == Opcode.AND
        assert instr.dst == 5
        assert instr.src1 == 1
        assert instr.src2 == 2

    def test_instruction_to_tuple(self, bytecode_module):
        """Test conversion to tuple for NumPy."""
        Instruction = bytecode_module.Instruction
        Opcode = bytecode_module.Opcode

        instr = Instruction(Opcode.LOAD_VAR, dst=3, immediate=7)
        tup = instr.to_tuple()
        assert tup == (Opcode.LOAD_VAR, 3, 0, 0, 0, 7, 0, 0)

    def test_instruction_validation(self, bytecode_module):
        """Test field validation."""
        Instruction = bytecode_module.Instruction
        Opcode = bytecode_module.Opcode

        with pytest.raises(ValueError, match="dst must be"):
            Instruction(Opcode.NOP, dst=15000)

        with pytest.raises(ValueError, match="immediate must be"):
            Instruction(Opcode.NOP, immediate=70000)

    def test_instruction_repr(self, bytecode_module):
        """Test instruction string representation."""
        Instruction = bytecode_module.Instruction
        Opcode = bytecode_module.Opcode

        assert "AND" in repr(Instruction(Opcode.AND, 5, 1, 2))
        assert "HALT" in repr(Instruction(Opcode.HALT))

class TestCompiler:
    """Test BytecodeCompiler."""

    def test_compile_simple_and(self, z3_module, bytecode_module):
        """Test compiling a AND b."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b = z3.Bools('a b')
        expr = z3.And(a, b)

        result = compile_constraint(expr, ['a', 'b'])

        assert result.num_variables == 2
        assert result.instruction_count > 0
        assert result.register_count <= 32

    def test_compile_simple_or(self, z3_module, bytecode_module):
        """Test compiling a OR b."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b = z3.Bools('a b')
        expr = z3.Or(a, b)

        result = compile_constraint(expr, ['a', 'b'])

        assert result.num_variables == 2
        assert result.instruction_count > 0

    def test_compile_not(self, z3_module, bytecode_module):
        """Test compiling NOT a."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a = z3.Bool('a')
        expr = z3.Not(a)

        result = compile_constraint(expr, ['a'])

        assert result.num_variables == 1
        assert result.instruction_count > 0

    def test_compile_implies(self, z3_module, bytecode_module):
        """Test compiling a => b."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b = z3.Bools('a b')
        expr = z3.Implies(a, b)

        result = compile_constraint(expr, ['a', 'b'])

        assert result.num_variables == 2
        assert result.instruction_count > 0

    def test_compile_complex(self, z3_module, bytecode_module):
        """Test compiling complex expression."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b, c, d = z3.Bools('a b c d')
        expr = z3.And(
            z3.Or(a, b),
            z3.Implies(c, z3.Not(d)),
            z3.Or(z3.Not(a), d)
        )

        result = compile_constraint(expr, ['a', 'b', 'c', 'd'])

        assert result.num_variables == 4
        assert result.instruction_count > 5

    def test_compile_constants(self, z3_module, bytecode_module):
        """Test compiling expressions with constants."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a = z3.Bool('a')
        expr = z3.And(a, z3.BoolVal(True))

        result = compile_constraint(expr, ['a'])
        assert result.num_variables == 1

    def test_compile_unknown_variable_error(self, z3_module, bytecode_module):
        """Test error on unknown variable."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b = z3.Bools('a b')
        expr = z3.And(a, b)

        with pytest.raises(ValueError, match="Unknown variable"):
            compile_constraint(expr, ['a'])               

    def test_compile_too_many_variables_error(self, z3_module, bytecode_module):
        """Test error on too many variables."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        vars = [z3.Bool(f'v{i}') for i in range(45)]
        expr = z3.And(*vars)

        with pytest.raises(ValueError, match="Too many variables"):
            compile_constraint(expr, [f'v{i}' for i in range(45)])

class TestCompiledConstraint:
    """Test CompiledConstraint dataclass."""

    def test_num_states(self, z3_module, bytecode_module):
        """Test num_states property."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b, c = z3.Bools('a b c')
        result = compile_constraint(z3.And(a, b, c), ['a', 'b', 'c'])

        assert result.num_states == 8       

    def test_output_bitmap_size(self, z3_module, bytecode_module):
        """Test output_bitmap_size property."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        vars = [z3.Bool(f'v{i}') for i in range(10)]
        result = compile_constraint(z3.And(*vars), [f'v{i}' for i in range(10)])

        assert result.output_bitmap_size == 128

    def test_memory_bytes(self, z3_module, bytecode_module):
        """Test memory_bytes calculation."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b = z3.Bools('a b')
        result = compile_constraint(z3.And(a, b), ['a', 'b'])

        assert result.memory_bytes() > result.output_bitmap_size

class TestDisassembler:
    """Test disassembler."""

    def test_disassemble_output(self, z3_module, bytecode_module):
        """Test disassemble produces readable output."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint
        disassemble = bytecode_module.disassemble

        a, b = z3.Bools('a b')
        compiled = compile_constraint(z3.And(a, b), ['a', 'b'])

        output = disassemble(compiled)

        assert "CompiledConstraint" in output
        assert "2 vars" in output
        assert "HALT" in output

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_single_variable(self, z3_module, bytecode_module):
        """Test single variable constraint."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a = z3.Bool('a')
        result = compile_constraint(a, ['a'])

        assert result.num_variables == 1
        assert result.num_states == 2

    def test_empty_and(self, z3_module, bytecode_module):
        """Test empty AND (should be TRUE)."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a = z3.Bool('a')
                                             
        expr = z3.And(a, z3.BoolVal(True))

        result = compile_constraint(expr, ['a'])
        assert result.num_variables == 1

    def test_deeply_nested(self, z3_module, bytecode_module):
        """Test deeply nested expression."""
        z3 = z3_module
        compile_constraint = bytecode_module.compile_constraint

        a, b, c = z3.Bools('a b c')

        expr = a
        for _ in range(5):
            expr = z3.And(expr, z3.Or(b, z3.Not(c)))
            expr = z3.Or(expr, z3.And(c, z3.Not(b)))

        result = compile_constraint(expr, ['a', 'b', 'c'])
        assert result.num_variables == 3
        assert result.register_count < 32                       
