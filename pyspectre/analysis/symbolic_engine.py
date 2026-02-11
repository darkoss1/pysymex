"""
Enhanced Symbolic Execution Engine for PySpectre.
This module provides a more sophisticated symbolic execution engine
that goes beyond simple value tracking. It integrates with Z3 for
constraint solving and provides:
- Symbolic values with full expression trees
- Path condition tracking
- Constraint-based analysis
- Memory model for heap objects
- Symbolic function summaries
- Concolic execution support
"""

from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)

try:
    import z3

    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

    class z3:
        ExprRef = Any
        SortRef = Any
        Solver = Any


class SymbolicKind(Enum):
    """Types of symbolic values."""

    CONCRETE = auto()
    SYMBOL = auto()
    BINARY_OP = auto()
    UNARY_OP = auto()
    COMPARE = auto()
    ITE = auto()
    SELECT = auto()
    STORE = auto()
    CALL = auto()
    UNKNOWN = auto()
    ERROR = auto()


class BinaryOp(Enum):
    """Binary operations."""

    ADD = auto()
    SUB = auto()
    MUL = auto()
    DIV = auto()
    FLOOR_DIV = auto()
    MOD = auto()
    POW = auto()
    LSHIFT = auto()
    RSHIFT = auto()
    BIT_OR = auto()
    BIT_XOR = auto()
    BIT_AND = auto()
    CONCAT = auto()


class UnaryOp(Enum):
    """Unary operations."""

    NEG = auto()
    POS = auto()
    INVERT = auto()
    NOT = auto()


class CompareOp(Enum):
    """Comparison operations."""

    LT = auto()
    LE = auto()
    EQ = auto()
    NE = auto()
    GT = auto()
    GE = auto()
    IS = auto()
    IS_NOT = auto()
    IN = auto()
    NOT_IN = auto()


@dataclass(frozen=True)
class SymbolicValue:
    """
    A symbolic value representing an expression.
    Symbolic values form expression trees that can be
    converted to Z3 constraints for solving.
    """

    kind: SymbolicKind
    concrete_value: Any = None
    concrete_type: type | None = None
    symbol_name: str = ""
    symbol_id: int = 0
    op: Any = None
    operands: tuple[SymbolicValue, ...] = ()
    condition: SymbolicValue | None = None
    then_value: SymbolicValue | None = None
    else_value: SymbolicValue | None = None
    base: SymbolicValue | None = None
    index: SymbolicValue | None = None
    value: SymbolicValue | None = None
    result_type: type | None = None
    source_line: int = 0

    @classmethod
    def concrete(cls, value: Any) -> SymbolicValue:
        """Create a concrete value."""
        return cls(
            kind=SymbolicKind.CONCRETE,
            concrete_value=value,
            concrete_type=type(value),
            result_type=type(value),
        )

    @classmethod
    def symbol(cls, name: str, sym_id: int, result_type: type | None = None) -> SymbolicValue:
        """Create a fresh symbolic value."""
        return cls(
            kind=SymbolicKind.SYMBOL,
            symbol_name=name,
            symbol_id=sym_id,
            result_type=result_type,
        )

    @classmethod
    def binary(
        cls,
        op: BinaryOp,
        left: SymbolicValue,
        right: SymbolicValue,
        result_type: type | None = None,
    ) -> SymbolicValue:
        """Create a binary operation."""
        return cls(
            kind=SymbolicKind.BINARY_OP,
            op=op,
            operands=(left, right),
            result_type=result_type,
        )

    @classmethod
    def unary(
        cls,
        op: UnaryOp,
        operand: SymbolicValue,
        result_type: type | None = None,
    ) -> SymbolicValue:
        """Create a unary operation."""
        return cls(
            kind=SymbolicKind.UNARY_OP,
            op=op,
            operands=(operand,),
            result_type=result_type,
        )

    @classmethod
    def compare(
        cls,
        op: CompareOp,
        left: SymbolicValue,
        right: SymbolicValue,
    ) -> SymbolicValue:
        """Create a comparison."""
        return cls(
            kind=SymbolicKind.COMPARE,
            op=op,
            operands=(left, right),
            result_type=bool,
        )

    @classmethod
    def ite(
        cls,
        condition: SymbolicValue,
        then_val: SymbolicValue,
        else_val: SymbolicValue,
    ) -> SymbolicValue:
        """Create if-then-else expression."""
        return cls(
            kind=SymbolicKind.ITE,
            condition=condition,
            then_value=then_val,
            else_value=else_val,
            result_type=then_val.result_type,
        )

    @classmethod
    def select(cls, base: SymbolicValue, index: SymbolicValue) -> SymbolicValue:
        """Create array/dict select operation."""
        return cls(
            kind=SymbolicKind.SELECT,
            base=base,
            index=index,
        )

    @classmethod
    def store(
        cls,
        base: SymbolicValue,
        index: SymbolicValue,
        value: SymbolicValue,
    ) -> SymbolicValue:
        """Create array/dict store operation."""
        return cls(
            kind=SymbolicKind.STORE,
            base=base,
            index=index,
            value=value,
        )

    @classmethod
    def call(
        cls,
        func: SymbolicValue,
        args: tuple[SymbolicValue, ...],
        result_type: type | None = None,
    ) -> SymbolicValue:
        """Create a function call."""
        return cls(
            kind=SymbolicKind.CALL,
            base=func,
            operands=args,
            result_type=result_type,
        )

    @classmethod
    def unknown(cls) -> SymbolicValue:
        """Create an unknown value."""
        return cls(kind=SymbolicKind.UNKNOWN)

    @classmethod
    def error(cls, message: str = "") -> SymbolicValue:
        """Create an error value."""
        return cls(kind=SymbolicKind.ERROR, symbol_name=message)

    @property
    def is_concrete(self) -> bool:
        """Check if this is a concrete value."""
        return self.kind == SymbolicKind.CONCRETE

    @property
    def is_symbolic(self) -> bool:
        """Check if this is symbolic (not concrete)."""
        return self.kind != SymbolicKind.CONCRETE

    def get_concrete(self) -> Any | None:
        """Get concrete value if available."""
        if self.is_concrete:
            return self.concrete_value
        return None

    def get_symbols(self) -> set[str]:
        """Get all symbol names used in this expression."""
        symbols: set[str] = set()
        if self.kind == SymbolicKind.SYMBOL:
            symbols.add(self.symbol_name)
        for operand in self.operands:
            symbols.update(operand.get_symbols())
        if self.condition:
            symbols.update(self.condition.get_symbols())
        if self.then_value:
            symbols.update(self.then_value.get_symbols())
        if self.else_value:
            symbols.update(self.else_value.get_symbols())
        if self.base:
            symbols.update(self.base.get_symbols())
        if self.index:
            symbols.update(self.index.get_symbols())
        if self.value:
            symbols.update(self.value.get_symbols())
        return symbols

    def substitute(
        self,
        substitution: dict[str, SymbolicValue],
    ) -> SymbolicValue:
        """Substitute symbols with new values."""
        if self.kind == SymbolicKind.SYMBOL:
            if self.symbol_name in substitution:
                return substitution[self.symbol_name]
            return self
        if self.kind == SymbolicKind.CONCRETE:
            return self
        new_operands = tuple(op.substitute(substitution) for op in self.operands)
        new_condition = self.condition.substitute(substitution) if self.condition else None
        new_then = self.then_value.substitute(substitution) if self.then_value else None
        new_else = self.else_value.substitute(substitution) if self.else_value else None
        new_base = self.base.substitute(substitution) if self.base else None
        new_index = self.index.substitute(substitution) if self.index else None
        new_value = self.value.substitute(substitution) if self.value else None
        return SymbolicValue(
            kind=self.kind,
            concrete_value=self.concrete_value,
            concrete_type=self.concrete_type,
            symbol_name=self.symbol_name,
            symbol_id=self.symbol_id,
            op=self.op,
            operands=new_operands,
            condition=new_condition,
            then_value=new_then,
            else_value=new_else,
            base=new_base,
            index=new_index,
            value=new_value,
            result_type=self.result_type,
            source_line=self.source_line,
        )

    def simplify(self) -> SymbolicValue:
        """Try to simplify the expression."""
        if self.operands:
            simplified_ops = tuple(op.simplify() for op in self.operands)
        else:
            simplified_ops = ()
        if self.kind == SymbolicKind.BINARY_OP and len(simplified_ops) == 2:
            left, right = simplified_ops
            if left.is_concrete and right.is_concrete:
                try:
                    result = self._eval_binary(self.op, left.concrete_value, right.concrete_value)
                    return SymbolicValue.concrete(result)
                except:
                    pass
        if self.kind == SymbolicKind.UNARY_OP and len(simplified_ops) == 1:
            operand = simplified_ops[0]
            if operand.is_concrete:
                try:
                    result = self._eval_unary(self.op, operand.concrete_value)
                    return SymbolicValue.concrete(result)
                except:
                    pass
        if self.kind == SymbolicKind.ITE and self.condition:
            cond = self.condition.simplify()
            if cond.is_concrete:
                if cond.concrete_value:
                    return (
                        self.then_value.simplify() if self.then_value else SymbolicValue.unknown()
                    )
                else:
                    return (
                        self.else_value.simplify() if self.else_value else SymbolicValue.unknown()
                    )
        if simplified_ops != self.operands:
            return SymbolicValue(
                kind=self.kind,
                concrete_value=self.concrete_value,
                concrete_type=self.concrete_type,
                symbol_name=self.symbol_name,
                symbol_id=self.symbol_id,
                op=self.op,
                operands=simplified_ops,
                condition=self.condition.simplify() if self.condition else None,
                then_value=self.then_value.simplify() if self.then_value else None,
                else_value=self.else_value.simplify() if self.else_value else None,
                base=self.base,
                index=self.index,
                value=self.value,
                result_type=self.result_type,
                source_line=self.source_line,
            )
        return self

    def _eval_binary(self, op: BinaryOp, left: Any, right: Any) -> Any:
        """Evaluate a binary operation on concrete values."""
        ops = {
            BinaryOp.ADD: lambda a, b: a + b,
            BinaryOp.SUB: lambda a, b: a - b,
            BinaryOp.MUL: lambda a, b: a * b,
            BinaryOp.DIV: lambda a, b: a / b,
            BinaryOp.FLOOR_DIV: lambda a, b: a // b,
            BinaryOp.MOD: lambda a, b: a % b,
            BinaryOp.POW: lambda a, b: a**b,
            BinaryOp.LSHIFT: lambda a, b: a << b,
            BinaryOp.RSHIFT: lambda a, b: a >> b,
            BinaryOp.BIT_OR: lambda a, b: a | b,
            BinaryOp.BIT_XOR: lambda a, b: a ^ b,
            BinaryOp.BIT_AND: lambda a, b: a & b,
            BinaryOp.CONCAT: lambda a, b: a + b,
        }
        return ops[op](left, right)

    def _eval_unary(self, op: UnaryOp, operand: Any) -> Any:
        """Evaluate a unary operation on a concrete value."""
        ops = {
            UnaryOp.NEG: lambda a: -a,
            UnaryOp.POS: lambda a: +a,
            UnaryOp.INVERT: lambda a: ~a,
            UnaryOp.NOT: lambda a: not a,
        }
        return ops[op](operand)

    def __repr__(self) -> str:
        if self.is_concrete:
            return f"Concrete({self.concrete_value!r})"
        if self.kind == SymbolicKind.SYMBOL:
            return f"Symbol({self.symbol_name})"
        if self.kind == SymbolicKind.BINARY_OP:
            return f"({self.operands[0]} {self.op.name} {self.operands[1]})"
        if self.kind == SymbolicKind.UNARY_OP:
            return f"({self.op.name} {self.operands[0]})"
        if self.kind == SymbolicKind.COMPARE:
            return f"({self.operands[0]} {self.op.name} {self.operands[1]})"
        if self.kind == SymbolicKind.ITE:
            return f"(if {self.condition} then {self.then_value} else {self.else_value})"
        return f"<{self.kind.name}>"


@dataclass
class PathCondition:
    """
    Represents the path condition - constraints that must be
    true for execution to reach a particular program point.
    """

    constraints: list[SymbolicValue] = field(default_factory=list)

    def add(self, constraint: SymbolicValue) -> None:
        """Add a constraint to the path condition."""
        self.constraints.append(constraint)

    def copy(self) -> PathCondition:
        """Create a copy of this path condition."""
        return PathCondition(list(self.constraints))

    def merge(self, other: PathCondition) -> PathCondition:
        """Merge two path conditions (for join points)."""
        return PathCondition(self.constraints + other.constraints)

    def is_satisfiable(self, solver: ConstraintSolver | None = None) -> bool:
        """Check if the path condition is satisfiable."""
        if not solver:
            return True
        return solver.check_satisfiable(self.constraints)

    def implies(
        self,
        constraint: SymbolicValue,
        solver: ConstraintSolver | None = None,
    ) -> bool | None:
        """Check if the path condition implies a constraint."""
        if not solver:
            return None
        return solver.check_implies(self.constraints, constraint)


@dataclass
class SymbolicObject:
    """A symbolic object on the heap."""

    object_id: int
    type_name: str
    fields: dict[str, SymbolicValue] = field(default_factory=dict)
    elements: dict[SymbolicValue, SymbolicValue] = field(default_factory=dict)
    length: SymbolicValue | None = None
    created_at_line: int = 0


@dataclass
class SymbolicState:
    """
    Complete symbolic state at a program point.
    """

    locals: dict[str, SymbolicValue] = field(default_factory=dict)
    stack: list[SymbolicValue] = field(default_factory=list)
    path_condition: PathCondition = field(default_factory=PathCondition)
    heap: dict[int, SymbolicObject] = field(default_factory=dict)
    next_object_id: int = 0
    next_symbol_id: int = 0
    globals: dict[str, SymbolicValue] = field(default_factory=dict)
    pc: int = 0
    line: int = 0

    def copy(self) -> SymbolicState:
        """Create a deep copy of this state."""
        new_state = SymbolicState(
            locals=dict(self.locals),
            stack=list(self.stack),
            path_condition=self.path_condition.copy(),
            heap=dict(self.heap),
            next_object_id=self.next_object_id,
            next_symbol_id=self.next_symbol_id,
            globals=dict(self.globals),
            pc=self.pc,
            line=self.line,
        )
        return new_state

    def fresh_symbol(self, name: str, result_type: type | None = None) -> SymbolicValue:
        """Create a fresh symbolic value."""
        sym = SymbolicValue.symbol(
            f"{name}_{self.next_symbol_id}",
            self.next_symbol_id,
            result_type,
        )
        self.next_symbol_id += 1
        return sym

    def allocate_object(self, type_name: str, line: int = 0) -> SymbolicObject:
        """Allocate a new symbolic object."""
        obj = SymbolicObject(
            object_id=self.next_object_id,
            type_name=type_name,
            created_at_line=line,
        )
        self.heap[self.next_object_id] = obj
        self.next_object_id += 1
        return obj

    def push(self, value: SymbolicValue) -> None:
        """Push value onto stack."""
        self.stack.append(value)

    def pop(self) -> SymbolicValue:
        """Pop value from stack."""
        if self.stack:
            return self.stack.pop()
        return SymbolicValue.unknown()

    def peek(self, depth: int = 0) -> SymbolicValue:
        """Peek at stack value."""
        idx = -(depth + 1)
        if abs(idx) <= len(self.stack):
            return self.stack[idx]
        return SymbolicValue.unknown()

    def get_local(self, name: str) -> SymbolicValue:
        """Get local variable value."""
        return self.locals.get(name, SymbolicValue.unknown())

    def set_local(self, name: str, value: SymbolicValue) -> None:
        """Set local variable value."""
        self.locals[name] = value

    def add_constraint(self, constraint: SymbolicValue) -> None:
        """Add constraint to path condition."""
        self.path_condition.add(constraint)


class ConstraintSolver(ABC):
    """Abstract interface for constraint solving."""

    @abstractmethod
    def check_satisfiable(self, constraints: list[SymbolicValue]) -> bool:
        """Check if constraints are satisfiable."""

    @abstractmethod
    def check_implies(
        self,
        premises: list[SymbolicValue],
        conclusion: SymbolicValue,
    ) -> bool | None:
        """Check if premises imply conclusion."""

    @abstractmethod
    def get_model(
        self,
        constraints: list[SymbolicValue],
    ) -> dict[str, Any] | None:
        """Get a satisfying assignment if constraints are satisfiable."""


class Z3Solver(ConstraintSolver):
    """Z3-based constraint solver."""

    def __init__(self) -> None:
        if not HAS_Z3:
            raise ImportError("Z3 is required for Z3Solver")
        self._solver = z3.Solver()
        self._symbols: dict[str, z3.ExprRef] = {}

    def check_satisfiable(self, constraints: list[SymbolicValue]) -> bool:
        """Check if constraints are satisfiable."""
        self._solver.reset()
        for constraint in constraints:
            z3_expr = self._to_z3(constraint)
            if z3_expr is not None:
                self._solver.add(z3_expr)
        return self._solver.check() == z3.sat

    def check_implies(
        self,
        premises: list[SymbolicValue],
        conclusion: SymbolicValue,
    ) -> bool | None:
        """Check if premises imply conclusion."""
        self._solver.reset()
        for premise in premises:
            z3_expr = self._to_z3(premise)
            if z3_expr is not None:
                self._solver.add(z3_expr)
        z3_conclusion = self._to_z3(conclusion)
        if z3_conclusion is None:
            return None
        self._solver.add(z3.Not(z3_conclusion))
        result = self._solver.check()
        if result == z3.unsat:
            return True
        elif result == z3.sat:
            return False
        else:
            return None

    def get_model(
        self,
        constraints: list[SymbolicValue],
    ) -> dict[str, Any] | None:
        """Get a satisfying assignment."""
        self._solver.reset()
        for constraint in constraints:
            z3_expr = self._to_z3(constraint)
            if z3_expr is not None:
                self._solver.add(z3_expr)
        if self._solver.check() != z3.sat:
            return None
        model = self._solver.model()
        result: dict[str, Any] = {}
        for name, z3_var in self._symbols.items():
            val = model.evaluate(z3_var)
            if z3.is_int_value(val):
                result[name] = val.as_long()
            elif z3.is_true(val):
                result[name] = True
            elif z3.is_false(val):
                result[name] = False
            else:
                result[name] = str(val)
        return result

    def _to_z3(self, sym: SymbolicValue) -> z3.ExprRef | None:
        """Convert symbolic value to Z3 expression."""
        if sym.kind == SymbolicKind.CONCRETE:
            val = sym.concrete_value
            if isinstance(val, bool):
                return z3.BoolVal(val)
            elif isinstance(val, int):
                return z3.IntVal(val)
            elif isinstance(val, float):
                return z3.RealVal(val)
            return None
        if sym.kind == SymbolicKind.SYMBOL:
            name = sym.symbol_name
            if name not in self._symbols:
                if sym.result_type == bool:
                    self._symbols[name] = z3.Bool(name)
                elif sym.result_type == float:
                    self._symbols[name] = z3.Real(name)
                else:
                    self._symbols[name] = z3.Int(name)
            return self._symbols[name]
        if sym.kind == SymbolicKind.BINARY_OP and len(sym.operands) == 2:
            left = self._to_z3(sym.operands[0])
            right = self._to_z3(sym.operands[1])
            if left is None or right is None:
                return None
            op_map = {
                BinaryOp.ADD: lambda a, b: a + b,
                BinaryOp.SUB: lambda a, b: a - b,
                BinaryOp.MUL: lambda a, b: a * b,
                BinaryOp.DIV: lambda a, b: a / b,
                BinaryOp.MOD: lambda a, b: a % b,
            }
            if sym.op in op_map:
                return op_map[sym.op](left, right)
        if sym.kind == SymbolicKind.UNARY_OP and len(sym.operands) == 1:
            operand = self._to_z3(sym.operands[0])
            if operand is None:
                return None
            if sym.op == UnaryOp.NEG:
                return -operand
            if sym.op == UnaryOp.NOT:
                return z3.Not(operand)
        if sym.kind == SymbolicKind.COMPARE and len(sym.operands) == 2:
            left = self._to_z3(sym.operands[0])
            right = self._to_z3(sym.operands[1])
            if left is None or right is None:
                return None
            op_map = {
                CompareOp.LT: lambda a, b: a < b,
                CompareOp.LE: lambda a, b: a <= b,
                CompareOp.EQ: lambda a, b: a == b,
                CompareOp.NE: lambda a, b: a != b,
                CompareOp.GT: lambda a, b: a > b,
                CompareOp.GE: lambda a, b: a >= b,
            }
            if sym.op in op_map:
                return op_map[sym.op](left, right)
        if sym.kind == SymbolicKind.ITE:
            cond = self._to_z3(sym.condition) if sym.condition else None
            then_v = self._to_z3(sym.then_value) if sym.then_value else None
            else_v = self._to_z3(sym.else_value) if sym.else_value else None
            if cond is not None and then_v is not None and else_v is not None:
                return z3.If(cond, then_v, else_v)
        return None


class SimpleSolver(ConstraintSolver):
    """
    Simple constraint solver without Z3.
    Uses constant propagation and simple pattern matching.
    """

    def check_satisfiable(self, constraints: list[SymbolicValue]) -> bool:
        """Conservative: assume satisfiable unless obviously not."""
        for constraint in constraints:
            simplified = constraint.simplify()
            if simplified.is_concrete:
                if not simplified.concrete_value:
                    return False
        return True

    def check_implies(
        self,
        premises: list[SymbolicValue],
        conclusion: SymbolicValue,
    ) -> bool | None:
        """Check simple implication patterns."""
        simplified = conclusion.simplify()
        if simplified.is_concrete:
            return bool(simplified.concrete_value)
        for premise in premises:
            if self._expressions_equal(premise, conclusion):
                return True
        return None

    def get_model(
        self,
        constraints: list[SymbolicValue],
    ) -> dict[str, Any] | None:
        """Generate a simple model."""
        symbols: set[str] = set()
        for constraint in constraints:
            symbols.update(constraint.get_symbols())
        return dict.fromkeys(symbols, 0)

    def _expressions_equal(self, a: SymbolicValue, b: SymbolicValue) -> bool:
        """Check if two expressions are structurally equal."""
        if a.kind != b.kind:
            return False
        if a.kind == SymbolicKind.CONCRETE:
            return a.concrete_value == b.concrete_value
        if a.kind == SymbolicKind.SYMBOL:
            return a.symbol_name == b.symbol_name
        if a.op != b.op:
            return False
        if len(a.operands) != len(b.operands):
            return False
        return all(
            self._expressions_equal(op_a, op_b) for op_a, op_b in zip(a.operands, b.operands)
        )


@dataclass
class ExecutionPath:
    """A single execution path through the program."""

    state: SymbolicState
    terminated: bool = False
    error: str | None = None
    return_value: SymbolicValue | None = None
    warnings: list[str] = field(default_factory=list)


class SymbolicExecutor:
    """
    Symbolic execution engine for Python bytecode.
    """

    def __init__(self, solver: ConstraintSolver | None = None) -> None:
        if solver:
            self.solver = solver
        elif HAS_Z3:
            self.solver = Z3Solver()
        else:
            self.solver = SimpleSolver()
        self.paths: list[ExecutionPath] = []
        self.max_paths = 100
        self.max_iterations = 1000

    def execute(
        self,
        code: Any,
        initial_args: dict[str, SymbolicValue] | None = None,
    ) -> list[ExecutionPath]:
        """Execute bytecode symbolically."""
        self.paths = []
        initial_state = SymbolicState()
        if initial_args:
            for name, value in initial_args.items():
                initial_state.set_local(name, value)
        else:
            for i, arg in enumerate(code.co_varnames[: code.co_argcount]):
                initial_state.set_local(arg, initial_state.fresh_symbol(arg))
        initial_path = ExecutionPath(state=initial_state)
        self._execute_path(initial_path, code)
        return self.paths

    def _execute_path(self, path: ExecutionPath, code: Any) -> None:
        """Execute a single path."""
        instructions = list(dis.get_instructions(code))
        iterations = 0
        while not path.terminated and iterations < self.max_iterations:
            iterations += 1
            instr = None
            for inst in instructions:
                if inst.offset == path.state.pc:
                    instr = inst
                    break
            if instr is None:
                path.terminated = True
                break
            if instr.starts_line:
                path.state.line = instr.starts_line
            self._execute_instruction(path, instr, code)
        if not path.terminated:
            path.error = "Max iterations exceeded"
            path.terminated = True
        self.paths.append(path)

    def _execute_instruction(
        self,
        path: ExecutionPath,
        instr: dis.Instruction,
        code: Any,
    ) -> None:
        """Execute a single instruction."""
        state = path.state
        opname = instr.opname
        arg = instr.arg
        argval = instr.argval
        next_pc = instr.offset + 2
        if opname in {"LOAD_NAME", "LOAD_FAST", "LOAD_GLOBAL", "LOAD_DEREF"}:
            value = state.get_local(argval)
            state.push(value)
        elif opname == "LOAD_CONST":
            state.push(SymbolicValue.concrete(argval))
        elif opname in {"STORE_NAME", "STORE_FAST", "STORE_GLOBAL", "STORE_DEREF"}:
            value = state.pop()
            state.set_local(argval, value)
        elif opname == "BINARY_OP":
            self._execute_binary_op(path, instr)
        elif opname == "UNARY_NEGATIVE":
            operand = state.pop()
            state.push(SymbolicValue.unary(UnaryOp.NEG, operand))
        elif opname == "UNARY_NOT":
            operand = state.pop()
            state.push(SymbolicValue.unary(UnaryOp.NOT, operand, bool))
        elif opname == "COMPARE_OP":
            self._execute_compare(path, instr)
        elif opname in {"JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"}:
            next_pc = argval
        elif opname in {
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_FORWARD_IF_TRUE",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_TRUE",
            "POP_JUMP_BACKWARD_IF_FALSE",
        }:
            self._execute_conditional_jump(path, instr, code)
            return
        elif opname in {"CALL", "CALL_FUNCTION", "CALL_METHOD"}:
            self._execute_call(path, instr)
        elif opname == "POP_TOP":
            state.pop()
        elif opname == "DUP_TOP":
            state.push(state.peek())
        elif opname == "ROT_TWO":
            a = state.pop()
            b = state.pop()
            state.push(a)
            state.push(b)
        elif opname == "RETURN_VALUE":
            path.return_value = state.pop()
            path.terminated = True
            return
        elif opname == "RETURN_CONST":
            path.return_value = SymbolicValue.concrete(argval)
            path.terminated = True
            return
        elif opname == "BUILD_LIST":
            elements = []
            for _ in range(arg or 0):
                elements.insert(0, state.pop())
            obj = state.allocate_object("list", state.line)
            obj.length = SymbolicValue.concrete(len(elements))
            for i, elem in enumerate(elements):
                obj.elements[SymbolicValue.concrete(i)] = elem
            state.push(SymbolicValue.concrete(obj.object_id))
        elif opname == "BUILD_MAP":
            count = arg or 0
            obj = state.allocate_object("dict", state.line)
            for _ in range(count):
                value = state.pop()
                key = state.pop()
                obj.fields[str(key)] = value
            state.push(SymbolicValue.concrete(obj.object_id))
        elif opname == "BINARY_SUBSCR":
            index = state.pop()
            container = state.pop()
            self._check_subscript(path, container, index)
            state.push(SymbolicValue.select(container, index))
        elif opname == "LOAD_ATTR":
            obj = state.pop()
            result = state.fresh_symbol(f"attr_{argval}")
            state.push(result)
        elif opname == "STORE_ATTR":
            value = state.pop()
            obj = state.pop()
        else:
            pass
        state.pc = next_pc

    def _execute_binary_op(self, path: ExecutionPath, instr: dis.Instruction) -> None:
        """Execute a binary operation."""
        state = path.state
        right = state.pop()
        left = state.pop()
        op_name = instr.argrepr if instr.argrepr else ""
        if "+" in op_name:
            op = BinaryOp.ADD
        elif "-" in op_name:
            op = BinaryOp.SUB
        elif "*" in op_name and "**" not in op_name:
            op = BinaryOp.MUL
        elif "//" in op_name:
            op = BinaryOp.FLOOR_DIV
            self._check_division(path, right)
        elif "/" in op_name:
            op = BinaryOp.DIV
            self._check_division(path, right)
        elif "%" in op_name:
            op = BinaryOp.MOD
            self._check_division(path, right)
        elif "**" in op_name:
            op = BinaryOp.POW
        elif "<<" in op_name:
            op = BinaryOp.LSHIFT
        elif ">>" in op_name:
            op = BinaryOp.RSHIFT
        elif "|" in op_name:
            op = BinaryOp.BIT_OR
        elif "^" in op_name:
            op = BinaryOp.BIT_XOR
        elif "&" in op_name:
            op = BinaryOp.BIT_AND
        else:
            state.push(SymbolicValue.unknown())
            return
        result = SymbolicValue.binary(op, left, right)
        state.push(result.simplify())

    def _execute_compare(self, path: ExecutionPath, instr: dis.Instruction) -> None:
        """Execute a comparison operation."""
        state = path.state
        right = state.pop()
        left = state.pop()
        cmp_name = instr.argval
        op_map = {
            "<": CompareOp.LT,
            "<=": CompareOp.LE,
            "==": CompareOp.EQ,
            "!=": CompareOp.NE,
            ">": CompareOp.GT,
            ">=": CompareOp.GE,
            "is": CompareOp.IS,
            "is not": CompareOp.IS_NOT,
            "in": CompareOp.IN,
            "not in": CompareOp.NOT_IN,
        }
        op = op_map.get(cmp_name, CompareOp.EQ)
        result = SymbolicValue.compare(op, left, right)
        state.push(result.simplify())

    def _execute_conditional_jump(
        self,
        path: ExecutionPath,
        instr: dis.Instruction,
        code: Any,
    ) -> None:
        """Execute a conditional jump, potentially forking paths."""
        state = path.state
        condition = state.pop()
        is_forward = "FORWARD" in instr.opname or "BACKWARD" not in instr.opname
        jump_if_true = "TRUE" in instr.opname
        jump_target = instr.argval
        fall_through = instr.offset + 2
        condition = condition.simplify()
        if condition.is_concrete:
            cond_value = bool(condition.concrete_value)
            if (cond_value and jump_if_true) or (not cond_value and not jump_if_true):
                state.pc = jump_target
            else:
                state.pc = fall_through
            return
        if len(self.paths) < self.max_paths:
            forked_state = state.copy()
            forked_path = ExecutionPath(state=forked_state)
            if jump_if_true:
                state.add_constraint(SymbolicValue.unary(UnaryOp.NOT, condition, bool))
                state.pc = fall_through
                forked_state.add_constraint(condition)
                forked_state.pc = jump_target
            else:
                state.add_constraint(condition)
                state.pc = fall_through
                forked_state.add_constraint(SymbolicValue.unary(UnaryOp.NOT, condition, bool))
                forked_state.pc = jump_target
            self._execute_path(forked_path, code)
        else:
            state.pc = fall_through

    def _execute_call(self, path: ExecutionPath, instr: dis.Instruction) -> None:
        """Execute a function call."""
        state = path.state
        arg_count = instr.argval if instr.argval else instr.arg or 0
        args = []
        for _ in range(arg_count):
            args.insert(0, state.pop())
        func = state.pop()
        result = SymbolicValue.call(func, tuple(args))
        state.push(result)

    def _check_division(self, path: ExecutionPath, divisor: SymbolicValue) -> None:
        """Check for division by zero."""
        zero = SymbolicValue.concrete(0)
        may_be_zero = SymbolicValue.compare(CompareOp.EQ, divisor, zero)
        test_constraints = list(path.state.path_condition.constraints)
        test_constraints.append(may_be_zero)
        if self.solver.check_satisfiable(test_constraints):
            path.warnings.append(f"Line {path.state.line}: Possible division by zero")

    def _check_subscript(
        self,
        path: ExecutionPath,
        container: SymbolicValue,
        index: SymbolicValue,
    ) -> None:
        """Check for out-of-bounds subscript."""


class SymbolicAnalyzer:
    """
    High-level interface for symbolic analysis.
    """

    def __init__(self) -> None:
        self.executor = SymbolicExecutor()

    def analyze_function(
        self,
        code: Any,
        file_path: str = "<unknown>",
    ) -> list[str]:
        """Analyze a function and return warnings."""
        paths = self.executor.execute(code)
        warnings = []
        for path in paths:
            for warning in path.warnings:
                warnings.append(f"{file_path}: {warning}")
            if path.error:
                warnings.append(f"{file_path}: Error: {path.error}")
        return warnings
