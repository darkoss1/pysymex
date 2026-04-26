import sys
import os

# Add the project root to sys.path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tests.repro.opcode_validator import validate_opcode


def run_tests():
    findings = []

    def check(success, msg):
        if not success:
            findings.append(msg)

    # --- UNARY OPCODES ---

    # UNARY_POSITIVE
    check(
        *validate_opcode(
            "x = +a",
            initial_values={"a": 5},
            expected_locals={"x": 5},
            description="UNARY_POSITIVE Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = +a",
            symbolic_vars={"a": "int"},
            initial_values={"a": 5},
            expected_locals={"x": 5},
            description="UNARY_POSITIVE Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = -a",
            initial_values={"a": 5},
            expected_locals={"x": -5},
            description="UNARY_NEGATIVE Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = -a",
            symbolic_vars={"a": "int"},
            initial_values={"a": 5},
            expected_locals={"x": -5},
            description="UNARY_NEGATIVE Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = not a",
            initial_values={"a": True},
            expected_locals={"x": False},
            description="UNARY_NOT Concrete True",
        )
    )
    check(
        *validate_opcode(
            "x = not a",
            initial_values={"a": False},
            expected_locals={"x": True},
            description="UNARY_NOT Concrete False",
        )
    )
    check(
        *validate_opcode(
            "x = not a",
            symbolic_vars={"a": "bool"},
            initial_values={"a": True},
            expected_locals={"x": False},
            description="UNARY_NOT Symbolic True",
        )
    )

    check(
        *validate_opcode(
            "x = ~a",
            initial_values={"a": 5},
            expected_locals={"x": -6},
            description="UNARY_INVERT Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = ~a",
            symbolic_vars={"a": "int"},
            initial_values={"a": 5},
            expected_locals={"x": -6},
            description="UNARY_INVERT Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a + b",
            initial_values={"a": 10, "b": 20},
            expected_locals={"x": 30},
            description="BINARY_ADD Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a + b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 10, "b": 20},
            expected_locals={"x": 30},
            description="BINARY_ADD Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a + b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 10, "b": 20},
            expected_locals={"x": 30},
            description="BINARY_ADD Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a - b",
            initial_values={"a": 30, "b": 10},
            expected_locals={"x": 20},
            description="BINARY_SUBTRACT Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a - b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 30, "b": 10},
            expected_locals={"x": 20},
            description="BINARY_SUBTRACT Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a - b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 30, "b": 10},
            expected_locals={"x": 20},
            description="BINARY_SUBTRACT Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a * b",
            initial_values={"a": 5, "b": 6},
            expected_locals={"x": 30},
            description="BINARY_MULTIPLY Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a * b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 5, "b": 6},
            expected_locals={"x": 30},
            description="BINARY_MULTIPLY Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a * b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 5, "b": 6},
            expected_locals={"x": 30},
            description="BINARY_MULTIPLY Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a // b",
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_FLOOR_DIVIDE Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a // b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_FLOOR_DIVIDE Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a // b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_FLOOR_DIVIDE Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a % b",
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 1},
            description="BINARY_MODULO Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a % b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 1},
            description="BINARY_MODULO Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a % b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 10, "b": 3},
            expected_locals={"x": 1},
            description="BINARY_MODULO Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a ** b",
            initial_values={"a": 2, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_POWER Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a ** b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 2, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_POWER Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a ** b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 2, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_POWER Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a << b",
            initial_values={"a": 1, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_LSHIFT Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a << b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 1, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_LSHIFT Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a << b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 1, "b": 3},
            expected_locals={"x": 8},
            description="BINARY_LSHIFT Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a >> b",
            initial_values={"a": 8, "b": 2},
            expected_locals={"x": 2},
            description="BINARY_RSHIFT Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a >> b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 8, "b": 2},
            expected_locals={"x": 2},
            description="BINARY_RSHIFT Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a >> b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 8, "b": 2},
            expected_locals={"x": 2},
            description="BINARY_RSHIFT Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a & b",
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_AND Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a & b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_AND Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a & b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 3},
            description="BINARY_AND Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a | b",
            initial_values={"a": 4, "b": 2},
            expected_locals={"x": 6},
            description="BINARY_OR Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a | b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 4, "b": 2},
            expected_locals={"x": 6},
            description="BINARY_OR Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a | b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 4, "b": 2},
            expected_locals={"x": 6},
            description="BINARY_OR Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a ^ b",
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 4},
            description="BINARY_XOR Concrete/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a ^ b",
            symbolic_vars={"a": "int"},
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 4},
            description="BINARY_XOR Symbolic/Concrete",
        )
    )
    check(
        *validate_opcode(
            "x = a ^ b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 7, "b": 3},
            expected_locals={"x": 4},
            description="BINARY_XOR Concrete/Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a / b", initial_values={"a": 10, "b": 0}, description="Division by Zero Concrete"
        )
    )
    check(
        *validate_opcode(
            "x = a / b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 10, "b": 0},
            description="Division by Zero Symbolic",
        )
    )

    check(
        *validate_opcode(
            "x = a % b", initial_values={"a": 10, "b": 0}, description="Modulo by Zero Concrete"
        )
    )
    check(
        *validate_opcode(
            "x = a % b",
            symbolic_vars={"b": "int"},
            initial_values={"a": 10, "b": 0},
            description="Modulo by Zero Symbolic",
        )
    )

    if not findings:
        print("All arithmetic opcodes passed validation.")
    else:
        for f in findings:
            print(f)


if __name__ == "__main__":
    run_tests()
