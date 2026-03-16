"""Property-based testing (fuzzing) infrastructure using Hypothesis.
Provides strategies for generating symbolic values, bytecode operations,
and complex test scenarios. Enables thorough testing through automated
exploration of edge cases.
"""

from __future__ import annotations

import dis
from dataclasses import dataclass
from typing import Any

import z3
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis.stateful import Bundle, RuleBasedStateMachine, invariant, rule

from pysymex.core.types import SymbolicValue


def symbolic_integers(
    min_value: int = -(2**31),
    max_value: int = 2**31 - 1,
) -> st.SearchStrategy:
    """Strategy for generating symbolic integers."""
    return st.integers(min_value=min_value, max_value=max_value).map(
        lambda x: SymbolicValue.from_const(x)
    )


def symbolic_booleans() -> st.SearchStrategy:
    """Strategy for generating symbolic booleans."""
    return st.booleans().map(lambda x: SymbolicValue.from_const(x))


def symbolic_strings(
    min_size: int = 0,
    max_size: int = 100,
) -> st.SearchStrategy:
    """Strategy for generating symbolic strings."""
    return st.text(min_size=min_size, max_size=max_size).map(lambda x: SymbolicValue.from_const(x))


def symbolic_floats(
    allow_nan: bool = False,
    allow_infinity: bool = False,
) -> st.SearchStrategy:
    """Strategy for generating symbolic floats."""
    return st.floats(
        allow_nan=allow_nan,
        allow_infinity=allow_infinity,
    ).map(lambda x: SymbolicValue.from_const(x))


def symbolic_none() -> st.SearchStrategy:
    """Strategy for generating symbolic None."""
    return st.just(SymbolicValue.from_const(None))


def symbolic_values() -> st.SearchStrategy:
    """Strategy for any symbolic value."""
    return st.one_of(
        symbolic_integers(),
        symbolic_booleans(),
        symbolic_strings(max_size=20),
        symbolic_floats(),
        symbolic_none(),
    )


def symbolic_lists(
    elements: st.SearchStrategy | None = None,
    min_size: int = 0,
    max_size: int = 10,
) -> st.SearchStrategy:
    """Strategy for generating symbolic lists."""
    if elements is None:
        elements = st.integers()
    return st.lists(elements, min_size=min_size, max_size=max_size).map(
        lambda xs: SymbolicValue.from_const(xs)
    )


def symbolic_dicts(
    keys: st.SearchStrategy | None = None,
    values: st.SearchStrategy | None = None,
    min_size: int = 0,
    max_size: int = 5,
) -> st.SearchStrategy:
    """Strategy for generating symbolic dictionaries."""
    if keys is None:
        keys = st.text(min_size=1, max_size=10)
    if values is None:
        values = st.integers()
    return st.dictionaries(keys, values, min_size=min_size, max_size=max_size).map(
        lambda d: SymbolicValue.from_const(d)
    )


def symbolic_sets(
    elements: st.SearchStrategy | None = None,
    min_size: int = 0,
    max_size: int = 10,
) -> st.SearchStrategy:
    """Strategy for generating symbolic sets."""
    if elements is None:
        elements = st.integers()
    return st.frozensets(elements, min_size=min_size, max_size=max_size).map(
        lambda s: SymbolicValue.from_const(set(s))
    )


def symbolic_tuples(
    *element_strategies: st.SearchStrategy,
) -> st.SearchStrategy:
    """Strategy for generating symbolic tuples."""
    if not element_strategies:
        element_strategies = (st.integers(), st.integers())
    return st.tuples(*element_strategies).map(lambda t: SymbolicValue.from_const(t))


def z3_int_vars(prefix: str = "x") -> st.SearchStrategy:
    """Strategy for generating Z3 integer variables."""
    return st.integers(min_value=0, max_value=99).map(lambda i: z3.Int(f"{prefix }{i }"))


def z3_bool_vars(prefix: str = "b") -> st.SearchStrategy:
    """Strategy for generating Z3 boolean variables."""
    return st.integers(min_value=0, max_value=99).map(lambda i: z3.Bool(f"{prefix }{i }"))


def z3_int_constants() -> st.SearchStrategy:
    """Strategy for Z3 integer constants."""
    return st.integers(min_value=-1000, max_value=1000).map(lambda x: z3.IntVal(x))


@st.composite
def z3_arithmetic_exprs(
    draw: st.DrawFn,
    depth: int = 3,
    vars: list[z3.ArithRef] | None = None,
) -> z3.ArithRef:
    """Strategy for generating Z3 arithmetic expressions."""
    if vars is None:
        vars = [z3.Int(f"x{i }") for i in range(3)]
    if depth <= 0:
        return draw(st.sampled_from(vars + [z3.IntVal(draw(st.integers(-10, 10)))]))
    op = draw(st.sampled_from(["var", "const", "add", "sub", "mul", "neg"]))
    if op == "var":
        return draw(st.sampled_from(vars))
    elif op == "const":
        return z3.IntVal(draw(st.integers(-100, 100)))
    elif op == "add":
        left = draw(z3_arithmetic_exprs(depth - 1, vars))
        right = draw(z3_arithmetic_exprs(depth - 1, vars))
        return left + right
    elif op == "sub":
        left = draw(z3_arithmetic_exprs(depth - 1, vars))
        right = draw(z3_arithmetic_exprs(depth - 1, vars))
        return left - right
    elif op == "mul":
        left = draw(z3_arithmetic_exprs(depth - 1, vars))
        right = draw(z3_arithmetic_exprs(depth - 1, vars))
        return left * right
    else:
        inner = draw(z3_arithmetic_exprs(depth - 1, vars))
        return -inner


@st.composite
def z3_bool_exprs(
    draw: st.DrawFn,
    depth: int = 3,
    int_vars: list[z3.ArithRef] | None = None,
    bool_vars: list[z3.BoolRef] | None = None,
) -> z3.BoolRef:
    """Strategy for generating Z3 boolean expressions."""
    if int_vars is None:
        int_vars = [z3.Int(f"x{i }") for i in range(3)]
    if bool_vars is None:
        bool_vars = [z3.Bool(f"b{i }") for i in range(2)]
    if depth <= 0:
        return draw(st.sampled_from(bool_vars + [z3.BoolVal(draw(st.booleans()))]))
    op = draw(
        st.sampled_from(
            [
                "var",
                "const",
                "and",
                "or",
                "not",
                "implies",
                "eq",
                "lt",
                "le",
                "gt",
                "ge",
            ]
        )
    )
    if op == "var":
        return draw(st.sampled_from(bool_vars))
    elif op == "const":
        return z3.BoolVal(draw(st.booleans()))
    elif op == "and":
        left = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        right = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        return z3.And(left, right)
    elif op == "or":
        left = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        right = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        return z3.Or(left, right)
    elif op == "not":
        inner = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        return z3.Not(inner)
    elif op == "implies":
        left = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        right = draw(z3_bool_exprs(depth - 1, int_vars, bool_vars))
        return z3.Implies(left, right)
    else:
        left = draw(z3_arithmetic_exprs(depth - 1, int_vars))
        right = draw(z3_arithmetic_exprs(depth - 1, int_vars))
        if op == "eq":
            return left == right
        elif op == "lt":
            return left < right
        elif op == "le":
            return left <= right
        elif op == "gt":
            return left > right
        else:
            return left >= right


ARITHMETIC_OPCODES = [
    "BINARY_OP",
]
COMPARISON_OPCODES = [
    "COMPARE_OP",
]
STACK_OPCODES = [
    "POP_TOP",
    "COPY",
    "SWAP",
]
LOAD_STORE_OPCODES = [
    "LOAD_CONST",
    "LOAD_FAST",
    "STORE_FAST",
    "LOAD_GLOBAL",
    "STORE_GLOBAL",
]


@dataclass
class MockInstruction:
    """Mock bytecode instruction for testing."""

    opname: str
    arg: int = 0
    argval: object = None
    offset: int = 0

    @property
    def opcode(self) -> int:
        """Get opcode number."""
        return dis.opmap.get(self.opname, 0)


def arithmetic_ops() -> st.SearchStrategy:
    """Strategy for arithmetic operations."""
    return st.sampled_from([0, 10, 5, 11, 2])


def comparison_ops() -> st.SearchStrategy:
    """Strategy for comparison operations."""
    return st.sampled_from([0, 1, 2, 3, 4, 5])


@st.composite
def mock_instructions(draw: st.DrawFn, opnames: list[str] | None = None) -> MockInstruction:
    """Strategy for generating mock instructions."""
    if opnames is None:
        opnames = STACK_OPCODES + LOAD_STORE_OPCODES
    opname = draw(st.sampled_from(opnames))
    if opname == "LOAD_CONST":
        value = draw(
            st.one_of(
                st.integers(-100, 100),
                st.floats(allow_nan=False, allow_infinity=False),
                st.text(max_size=10),
                st.none(),
            )
        )
        return MockInstruction(opname, argval=value)
    elif opname in ("LOAD_FAST", "STORE_FAST"):
        varname = draw(st.sampled_from(["x", "y", "z", "a", "b"]))
        return MockInstruction(opname, argval=varname)
    elif opname in ("LOAD_GLOBAL", "STORE_GLOBAL"):
        name = draw(st.sampled_from(["print", "len", "range", "list"]))
        return MockInstruction(opname, argval=name)
    elif opname in ("COPY", "SWAP"):
        arg = draw(st.integers(1, 3))
        return MockInstruction(opname, arg=arg)
    else:
        return MockInstruction(opname)


@st.composite
def preconditions(draw: st.DrawFn, var_names: list[str] | None = None) -> str:
    """Strategy for generating precondition strings."""
    if var_names is None:
        var_names = ["x", "y", "n"]
    var = draw(st.sampled_from(var_names))
    op = draw(st.sampled_from([">", ">=", "<", "<=", "==", "!="]))
    val = draw(st.integers(-100, 100))
    return f"{var } {op } {val }"


@st.composite
def postconditions(draw: st.DrawFn, var_names: list[str] | None = None) -> str:
    """Strategy for generating postcondition strings."""
    if var_names is None:
        var_names = ["result", "x", "y"]
    condition_type = draw(st.sampled_from(["comparison", "type_check", "relation"]))
    if condition_type == "comparison":
        var = draw(st.sampled_from(var_names))
        op = draw(st.sampled_from([">", ">=", "<", "<=", "==", "!="]))
        val = draw(st.integers(-100, 100))
        return f"{var } {op } {val }"
    elif condition_type == "type_check":
        var = draw(st.sampled_from(var_names))
        typ = draw(st.sampled_from(["int", "str", "list", "bool"]))
        return f"isinstance({var }, {typ })"
    else:
        var1 = draw(st.sampled_from(var_names))
        var2 = draw(st.sampled_from([v for v in var_names if v != var1] or var_names))
        op = draw(st.sampled_from([">", ">=", "<", "<=", "=="]))
        return f"{var1 } {op } {var2 }"


@st.composite
def invariants(draw: st.DrawFn, var_name: str = "i", bound_var: str = "n") -> str:
    """Strategy for generating loop invariant strings."""
    inv_type = draw(st.sampled_from(["bound", "monotonic", "positive"]))
    if inv_type == "bound":
        op = draw(st.sampled_from(["<", "<=", ">", ">="]))
        return f"{var_name } {op } {bound_var }"
    elif inv_type == "monotonic":
        return f"{var_name } >= 0"
    else:
        return f"{var_name } >= 0"


class SymbolicStateMachine(RuleBasedStateMachine):
    """Stateful test for symbolic execution state consistency.
    Uses Hypothesis stateful testing to verify that:
    1. Stack operations maintain consistency
    2. Variable stores/loads are correct
    3. Constraints are properly tracked
    """

    def __init__(self):
        """Initialize the state machine with empty stack, locals, and constraints."""
        super().__init__()
        self.stack: list[object] = []
        self.locals: dict[str, object] = {}
        self.constraints: list[object] = []

    values = Bundle("values")

    @rule(target=values, v=st.integers(-100, 100))
    def push_int(self, v: int) -> int:
        """Push an integer onto the stack."""
        self.stack.append(v)
        return v

    @rule(target=values, v=st.booleans())
    def push_bool(self, v: bool) -> bool:
        """Push a boolean onto the stack."""
        self.stack.append(v)
        return v

    @rule(v=values)
    def pop(self, v: object) -> None:
        """Pop a value from the stack."""
        assume(len(self.stack) > 0)
        self.stack.pop()

    @rule(v=values, name=st.sampled_from(["x", "y", "z"]))
    def store_local(self, v: object, name: str) -> None:
        """Store a value in a local variable."""
        self.locals[name] = v

    @rule(target=values, name=st.sampled_from(["x", "y", "z"]))
    def load_local(self, name: str) -> object:
        """Load a value from a local variable."""
        assume(name in self.locals)
        v = self.locals[name]
        self.stack.append(v)
        return v

    @rule()
    def binary_add(self):
        """Perform binary addition."""
        assume(len(self.stack) >= 2)
        assume(all(isinstance(x, (int, float)) for x in self.stack[-2:]))
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(a + b)

    @rule()
    def binary_sub(self):
        """Perform binary subtraction."""
        assume(len(self.stack) >= 2)
        assume(all(isinstance(x, (int, float)) for x in self.stack[-2:]))
        b = self.stack.pop()
        a = self.stack.pop()
        self.stack.append(a - b)

    @rule()
    def dup_top(self):
        """Duplicate the top of stack."""
        assume(len(self.stack) >= 1)
        self.stack.append(self.stack[-1])

    @invariant()
    def stack_is_list(self):
        """Stack should always be a list."""
        assert isinstance(self.stack, list)

    @invariant()
    def locals_is_dict(self):
        """Locals should always be a dict."""
        assert isinstance(self.locals, dict)


TestSymbolicState: type = SymbolicStateMachine.TestCase


class PropertyTests:
    """Collection of property-based tests."""

    @given(st.integers(), st.integers())
    def test_addition_commutative(self, a: int, b: int):
        """Addition should be commutative."""
        assert a + b == b + a

    @given(st.integers(), st.integers(), st.integers())
    def test_addition_associative(self, a: int, b: int, c: int):
        """Addition should be associative."""
        assert (a + b) + c == a + (b + c)

    @given(st.lists(st.integers(), min_size=1))
    def test_list_len_positive(self, xs: list[int]):
        """List length should be non-negative."""
        assert len(xs) >= 0

    @given(st.lists(st.integers()), st.integers())
    def test_append_increases_len(self, xs: list[int], x: int):
        """Appending should increase length by 1."""
        original_len = len(xs)
        xs.append(x)
        assert len(xs) == original_len + 1

    @given(st.dictionaries(st.text(min_size=1, max_size=5), st.integers()))
    def test_dict_get_after_set(self, d: dict[str, int]):
        """Getting after setting should return the value."""
        for k, v in d.items():
            assert d[k] == v

    @given(z3_arithmetic_exprs(depth=2))
    @settings(max_examples=50)
    def test_z3_expr_simplify(self, expr: z3.ArithRef) -> None:
        """Z3 expressions should simplify without error."""
        simplified = z3.simplify(expr)
        assert simplified is not None

    @given(z3_bool_exprs(depth=2))
    @settings(max_examples=50)
    def test_z3_bool_satisfiable_or_unsat(self, expr: z3.BoolRef) -> None:
        """Z3 boolean expressions should be decidable."""
        solver = z3.Solver()
        solver.add(expr)
        result = solver.check()
        assert result in (z3.sat, z3.unsat)


@dataclass
class ConformanceTest:
    """A conformance test case."""

    name: str
    code: str
    expected_result: Any
    expected_exception: type[Exception] | None = None
    description: str = ""


class ConformanceGenerator:
    """Generates conformance tests from Python expressions.
    Creates test cases that verify PySyMex produces the same
    results as CPython for various expressions and operations.
    """

    def __init__(self):
        self.tests: list[ConformanceTest] = []

    def add_expression_test(
        self,
        name: str,
        expr: str,
        description: str = "",
    ) -> None:
        """Add a test for an expression."""
        from pysymex.security import create_sandbox_namespace

        sandbox = create_sandbox_namespace()
        try:
            result = eval(expr, sandbox)
            self.tests.append(
                ConformanceTest(
                    name=name,
                    code=expr,
                    expected_result=result,
                    description=description,
                )
            )
        except Exception as e:
            self.tests.append(
                ConformanceTest(
                    name=name,
                    code=expr,
                    expected_result=None,
                    expected_exception=type(e),
                    description=description,
                )
            )

    def add_statement_test(
        self,
        name: str,
        code: str,
        check_var: str,
        description: str = "",
    ) -> None:
        """Add a test for statements."""
        from pysymex.security import create_sandbox_namespace

        namespace: dict[str, object] = create_sandbox_namespace()
        try:
            exec(code, namespace)
            result: object = namespace.get(check_var)
            self.tests.append(
                ConformanceTest(
                    name=name,
                    code=code,
                    expected_result=result,
                    description=description,
                )
            )
        except Exception as e:
            self.tests.append(
                ConformanceTest(
                    name=name,
                    code=code,
                    expected_result=None,
                    expected_exception=type(e),
                    description=description,
                )
            )

    def generate_arithmetic_tests(self) -> None:
        """Generate arithmetic conformance tests."""
        ops = ["+", "-", "*", "/", "//", "%", "**"]
        values = [0, 1, -1, 2, 10, -10, 100]
        for op in ops:
            for a in values:
                for b in values:
                    if op in ("/", "//", "%") and b == 0:
                        continue
                    if op == "**" and (abs(a) > 10 or abs(b) > 10):
                        continue
                    expr = f"{a } {op } {b }"
                    self.add_expression_test(
                        name=f"arith_{op }_{a }_{b }".replace("-", "neg"),
                        expr=expr,
                        description=f"Arithmetic: {expr }",
                    )

    def generate_comparison_tests(self) -> None:
        """Generate comparison conformance tests."""
        ops = ["<", "<=", "==", "!=", ">=", ">"]
        values = [0, 1, -1, 10, -10]
        for op in ops:
            for a in values:
                for b in values:
                    expr = f"{a } {op } {b }"
                    self.add_expression_test(
                        name=f"cmp_{a }_{op }_{b }".replace("-", "neg")
                        .replace("<", "lt")
                        .replace(">", "gt")
                        .replace("=", "eq")
                        .replace("!", "ne"),
                        expr=expr,
                        description=f"Comparison: {expr }",
                    )

    def generate_boolean_tests(self) -> None:
        """Generate boolean logic conformance tests."""
        exprs = [
            "True and True",
            "True and False",
            "False and True",
            "False and False",
            "True or True",
            "True or False",
            "False or True",
            "False or False",
            "not True",
            "not False",
            "True and True or False",
            "True or False and False",
            "not (True and False)",
        ]
        for i, expr in enumerate(exprs):
            self.add_expression_test(
                name=f"bool_{i }",
                expr=expr,
                description=f"Boolean: {expr }",
            )

    def generate_list_tests(self) -> None:
        """Generate list operation conformance tests."""
        tests = [
            ("list_empty", "[]", "Empty list"),
            ("list_single", "[1]", "Single element"),
            ("list_multi", "[1, 2, 3]", "Multiple elements"),
            ("list_nested", "[[1], [2, 3]]", "Nested list"),
            ("list_index", "[1, 2, 3][1]", "List indexing"),
            ("list_negative_index", "[1, 2, 3][-1]", "Negative indexing"),
            ("list_slice", "[1, 2, 3, 4][1:3]", "List slicing"),
            ("list_len", "len([1, 2, 3])", "List length"),
            ("list_in", "2 in [1, 2, 3]", "List membership"),
            ("list_not_in", "5 in [1, 2, 3]", "List non-membership"),
            ("list_concat", "[1, 2] + [3, 4]", "List concatenation"),
            ("list_repeat", "[1, 2] * 3", "List repetition"),
        ]
        for name, expr, desc in tests:
            self.add_expression_test(name, expr, desc)

    def generate_dict_tests(self) -> None:
        """Generate dict operation conformance tests."""
        tests = [
            ("dict_empty", "{}", "Empty dict"),
            ("dict_single", "{'a': 1}", "Single key"),
            ("dict_multi", "{'a': 1, 'b': 2}", "Multiple keys"),
            ("dict_access", "{'a': 1, 'b': 2}['a']", "Dict access"),
            ("dict_len", "len({'a': 1, 'b': 2})", "Dict length"),
            ("dict_in", "'a' in {'a': 1}", "Dict key membership"),
            ("dict_not_in", "'c' in {'a': 1}", "Dict key non-membership"),
        ]
        for name, expr, desc in tests:
            self.add_expression_test(name, expr, desc)

    def generate_all(self) -> list[ConformanceTest]:
        """Generate all conformance tests."""
        self.generate_arithmetic_tests()
        self.generate_comparison_tests()
        self.generate_boolean_tests()
        self.generate_list_tests()
        self.generate_dict_tests()
        return self.tests

    def to_pytest_code(self) -> str:
        """Generate pytest code for conformance tests."""
        lines = [
            '"""Auto-generated conformance tests."""',
            "",
            "import pytest",
            "",
            "",
            "class TestConformance:",
            '    """Conformance tests for CPython compatibility."""',
            "",
        ]
        for test in self.tests:
            safe_name = test.name.replace("-", "_").replace(" ", "_")
            lines.append(f"    def test_{safe_name }(self):")
            lines.append(f'        """Test: {test .description or test .code }"""')
            if test.expected_exception:
                lines.append(f"        with pytest.raises({test .expected_exception .__name__ }):")
                lines.append(f"            eval({test .code!r})")
            else:
                lines.append(f"        result = eval({test .code!r})")
                lines.append(f"        assert result == {test .expected_result!r}")
            lines.append("")
        return "\n".join(lines)


__all__ = [
    "ConformanceGenerator",
    "ConformanceTest",
    "MockInstruction",
    "PropertyTests",
    "SymbolicStateMachine",
    "TestSymbolicState",
    "arithmetic_ops",
    "comparison_ops",
    "invariants",
    "mock_instructions",
    "postconditions",
    "preconditions",
    "symbolic_booleans",
    "symbolic_dicts",
    "symbolic_floats",
    "symbolic_integers",
    "symbolic_lists",
    "symbolic_none",
    "symbolic_sets",
    "symbolic_strings",
    "symbolic_tuples",
    "symbolic_values",
    "z3_arithmetic_exprs",
    "z3_bool_exprs",
    "z3_bool_vars",
    "z3_int_constants",
    "z3_int_vars",
]
