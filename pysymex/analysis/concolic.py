"""Concolic (Concrete + Symbolic) execution for pysymex.
Concolic execution combines concrete execution with symbolic constraint
collection, enabling more scalable analysis of real programs.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass, field

import z3

from pysymex.core.solver import create_solver


@dataclass
class ConcreteInput:
    """A concrete input assignment for testing."""

    values: dict[str, object]
    generation: int = 0
    parent: ConcreteInput | None = None
    branch_flipped: int | None = None

    def __hash__(self) -> int:
        return hash(frozenset(self.values.items()))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConcreteInput):
            return False
        return self.values == other.values


@dataclass
class BranchRecord:
    """Records a branch decision during concrete execution."""

    pc: int
    condition: z3.BoolRef
    taken: bool
    line_number: int | None = None

    def negate(self) -> z3.BoolRef:
        """Get the negated branch condition."""
        if self.taken:
            return z3.Not(self.condition)
        return self.condition


@dataclass
class ExecutionTrace:
    """Records the execution trace of a concrete run."""

    input: ConcreteInput
    branches: list[BranchRecord] = field(default_factory=list[BranchRecord])
    coverage: set[int] = field(default_factory=set[int])
    result: object = None
    exception: Exception | None = None

    def path_condition(self) -> list[z3.BoolRef]:
        """Get the path condition for this trace."""
        conditions: list[z3.BoolRef] = []
        for branch in self.branches:
            if branch.taken:
                conditions.append(branch.condition)
            else:
                conditions.append(z3.Not(branch.condition))
        return conditions

    def path_hash(self) -> int:
        """Hash of the execution path for deduplication."""
        return hash(tuple((b.pc, b.taken) for b in self.branches))


class ConcolicExecutor:
    """Concolic execution engine.
    This engine runs functions concretely while collecting symbolic
    constraints, then uses constraint solving to generate new test
    inputs that explore different paths.
    """

    def __init__(
        self,
        max_iterations: int = 100,
        max_time_seconds: float = 300.0,
        strategy: str = "dfs",
    ):
        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
        self.strategy = strategy
        self._traces: list[ExecutionTrace] = []
        self._seen_paths: set[int] = set()
        self._worklist: list[tuple[ConcreteInput, int]] = []
        self._coverage: set[int] = set()
        self._iteration: int = 0

    def execute(
        self,
        func: Callable[..., object],
        initial_inputs: dict[str, object] | None = None,
        symbolic_types: dict[str, str] | None = None,
    ) -> ConcolicResult:
        """Execute function concolically.
        Args:
            func: Function to analyze
            initial_inputs: Initial concrete values for parameters
            symbolic_types: Types of symbolic parameters
        Returns:
            ConcolicResult with all discovered paths and issues
        """
        import time

        start_time = time.time()
        self._reset()
        if initial_inputs is None:
            initial_inputs = self._generate_random_inputs(func, symbolic_types or {})
        initial = ConcreteInput(values=initial_inputs, generation=0)
        self._worklist.append((initial, -1))
        while self._worklist and self._iteration < self.max_iterations:
            if time.time() - start_time > self.max_time_seconds:
                break
            concrete_input, _branch_idx = self._get_next_input()
            trace = self._execute_concrete(func, concrete_input)
            path_hash = trace.path_hash()
            if path_hash in self._seen_paths:
                continue
            self._seen_paths.add(path_hash)
            self._traces.append(trace)
            self._coverage.update(trace.coverage)
            self._iteration += 1
            self._expand_worklist(trace)
        return ConcolicResult(
            traces=self._traces,
            coverage=self._coverage,
            iterations=self._iteration,
            time_seconds=time.time() - start_time,
        )

    def _reset(self) -> None:
        """Reset execution state."""
        self._traces = []
        self._seen_paths = set()
        self._worklist = []
        self._coverage = set()
        self._iteration = 0

    def _generate_random_inputs(
        self,
        func: Callable[..., object],
        symbolic_types: dict[str, str],
    ) -> dict[str, object]:
        """Generate random initial inputs."""
        import inspect

        try:
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
        except (ValueError, TypeError):
            params = list(func.__code__.co_varnames[: func.__code__.co_argcount])
        inputs: dict[str, object] = {}
        for param in params:
            type_hint = symbolic_types.get(param, "int")
            if type_hint in ("int", "integer"):
                inputs[param] = random.randint(-100, 100)
            elif type_hint in ("str", "string"):
                inputs[param] = "".join(
                    chr(random.randint(97, 122)) for _ in range(random.randint(1, 10))
                )
            elif type_hint in ("bool", "boolean"):
                inputs[param] = random.choice([True, False])
            elif type_hint in ("float", "real"):
                inputs[param] = random.uniform(-100.0, 100.0)
            elif type_hint in ("list", "array"):
                inputs[param] = [random.randint(-10, 10) for _ in range(random.randint(0, 5))]
            else:
                inputs[param] = 0
        return inputs

    def _get_next_input(self) -> tuple[ConcreteInput, int]:
        """Get the next input from the worklist based on strategy."""
        if self.strategy == "dfs":
            return self._worklist.pop()
        elif self.strategy == "bfs":
            return self._worklist.pop(0)
        elif self.strategy == "random":
            idx = random.randint(0, len(self._worklist) - 1)
            return self._worklist.pop(idx)
        else:
            return self._worklist.pop()

    def _execute_concrete(
        self,
        func: Callable[..., object],
        concrete_input: ConcreteInput,
    ) -> ExecutionTrace:
        """Execute function with concrete values while tracking symbolically."""
        from pysymex.execution.executor import ExecutionConfig, SymbolicExecutor

        trace = ExecutionTrace(input=concrete_input)
        config = ExecutionConfig(max_paths=1)
        executor = SymbolicExecutor(config)
        symbolic_args: dict[str, str] = {}
        for name, value in concrete_input.values.items():
            if isinstance(value, int):
                symbolic_args[name] = "int"
            elif isinstance(value, str):
                symbolic_args[name] = "str"
            elif isinstance(value, bool):
                symbolic_args[name] = "bool"
            else:
                symbolic_args[name] = "int"
        try:
            result = executor.execute_function(func, symbolic_args, initial_values=concrete_input.values)
            trace.coverage = result.coverage
            trace.result = result
            trace.branches = [
                BranchRecord(pc=b.pc, condition=b.condition, taken=b.taken)
                for b in getattr(result, "branches", [])
            ]
        except Exception as e:
            trace.exception = e
        return trace

    def _expand_worklist(self, trace: ExecutionTrace) -> None:
        """Generate new inputs by negating branches in the trace."""
        for i, branch in enumerate(trace.branches):
            prefix = [b.condition if b.taken else z3.Not(b.condition) for b in trace.branches[:i]]
            prefix.append(branch.negate())
            solver = create_solver()
            solver.add(*prefix)
            if solver.check() == z3.sat:
                model = solver.model()
                new_values: dict[str, object] = {}
                for name, value in trace.input.values.items():
                    for decl in model.decls():
                        if decl.name() == name or decl.name().startswith(f"{name}_"):
                            val = model[decl]
                            new_values[name] = self._z3_to_python(val)
                            break
                    else:
                        new_values[name] = value
                new_input = ConcreteInput(
                    values=new_values,
                    generation=trace.input.generation + 1,
                    parent=trace.input,
                    branch_flipped=i,
                )
                self._worklist.append((new_input, i))

    def _z3_to_python(self, z3_val: z3.ExprRef) -> object:
        """Convert Z3 value to Python value."""
        if z3.is_int(z3_val):
            return z3_val.as_long()
        elif z3.is_bool(z3_val):
            return z3.is_true(z3_val)
        elif z3.is_string(z3_val):
            return z3_val.as_string()
        elif z3.is_real(z3_val):
            return float(z3_val.as_decimal(10))
        else:
            return str(z3_val)


@dataclass
class ConcolicResult:
    """Result of concolic execution."""

    traces: list[ExecutionTrace]
    coverage: set[int]
    iterations: int
    time_seconds: float

    @property
    def num_paths(self) -> int:
        """Number of unique paths discovered."""
        return len(self.traces)

    @property
    def coverage_percentage(self) -> float:
        """Estimate of coverage (if total is known)."""
        return len(self.coverage)

    def get_failing_inputs(self) -> list[ConcreteInput]:
        """Get inputs that caused exceptions."""
        return [trace.input for trace in self.traces if trace.exception is not None]

    def format_summary(self) -> str:
        """Format a summary of results."""
        lines = [
            "=== Concolic Execution Summary ===",
            f"Iterations: {self .iterations }",
            f"Unique paths: {self .num_paths }",
            f"Coverage: {len (self .coverage )} instructions",
            f"Time: {self .time_seconds :.2f}s",
        ]
        failing = self.get_failing_inputs()
        if failing:
            lines.append(f"\nFailing inputs: {len (failing )}")
            for inp in failing[:5]:
                lines.append(f"  {inp .values }")
        return "\n".join(lines)


class GenerationalSearch:
    """SAGE-style generational search.
    SAGE (Scalable Automated Guided Execution) is a coverage-guided
    testing technique that systematically explores paths.
    """

    def __init__(self, max_generations: int = 10):
        self.max_generations = max_generations
        self._generations: list[list[ConcreteInput]] = []

    def search(
        self,
        func: Callable[..., object],
        initial_input: dict[str, object],
        symbolic_types: dict[str, str],
    ) -> list[ExecutionTrace]:
        """Perform generational search.
        Generation 0: Run with initial input
        Generation N: Run with inputs derived from generation N-1
        """
        executor = ConcolicExecutor(strategy="coverage")
        gen0 = ConcreteInput(values=initial_input, generation=0)
        self._generations.append([gen0])
        all_traces: list[ExecutionTrace] = []
        for gen in range(self.max_generations):
            if gen >= len(self._generations):
                break
            current_gen = self._generations[gen]
            next_gen: list[ConcreteInput] = []
            for input_val in current_gen:
                result = executor.execute(
                    func,
                    initial_inputs=input_val.values,
                    symbolic_types=symbolic_types,
                )
                all_traces.extend(result.traces)
                for trace in result.traces:
                    if trace.input.generation == gen + 1:
                        next_gen.append(trace.input)
            if next_gen:
                self._generations.append(next_gen)
        return all_traces


__all__ = [
    "BranchRecord",
    "ConcolicExecutor",
    "ConcolicResult",
    "ConcreteInput",
    "ExecutionTrace",
    "GenerationalSearch",
]
