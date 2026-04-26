import dis
from tests.repro.opcode_validator import validate_opcode


def run_test(description, code, symbolic_vars=None, initial_values=None, expected_locals=None):
    success, msg = validate_opcode(
        code,
        symbolic_vars=symbolic_vars,
        initial_values=initial_values,
        expected_locals=expected_locals,
        description=description,
    )
    print(f"{description}: {msg}")
    return success


def validate_comparisons():
    print("\n--- Validating Comparison Opcodes ---")

    # COMPARE_OP
    run_test(
        "COMPARE_OP Concrete/Concrete (1 < 2)",
        "z = (x < y)",
        initial_values={"x": 1, "y": 2},
        expected_locals={"z": True},
    )
    run_test(
        "COMPARE_OP Symbolic/Concrete (x < 10, x=5)",
        "z = (x < y)",
        symbolic_vars={"x": "int"},
        initial_values={"x": 5, "y": 10},
        expected_locals={"z": True},
    )
    run_test(
        "COMPARE_OP Concrete/Symbolic (10 < x, x=15)",
        "z = (y < x)",
        symbolic_vars={"x": "int"},
        initial_values={"x": 15, "y": 10},
        expected_locals={"z": True},
    )

    run_test(
        "IS_OP Concrete (None is None)",
        "z = (x is y)",
        initial_values={"x": None, "y": None},
        expected_locals={"z": True},
    )
    run_test(
        "IS_OP Symbolic (x is None, x=None)",
        "z = (x is None)",
        symbolic_vars={"x": "int"},
        initial_values={"x": None},
        expected_locals={"z": True},
    )
    run_test(
        "IS_OP Symbolic (x is not None, x=5)",
        "z = (x is not None)",
        symbolic_vars={"x": "int"},
        initial_values={"x": 5},
        expected_locals={"z": True},
    )

    run_test(
        "CONTAINS_OP Concrete (1 in [1, 2])",
        "z = (x in y)",
        initial_values={"x": 1, "y": [1, 2]},
        expected_locals={"z": True},
    )
    run_test(
        "CONTAINS_OP Concrete (3 not in [1, 2])",
        "z = (x not in y)",
        initial_values={"x": 3, "y": [1, 2]},
        expected_locals={"z": True},
    )
    run_test(
        "CONTAINS_OP Symbolic/Concrete (x in [1, 2], x=1)",
        "z = (x in [1, 2])",
        symbolic_vars={"x": "int"},
        initial_values={"x": 1},
        expected_locals={"z": True},
    )


def validate_control_flow():
    print("\n--- Validating Control Flow Opcodes ---")

    code_if = """
if x < 10:
    z = 1
else:
    z = 2
"""
    run_test("IF (True branch, x=5)", code_if, initial_values={"x": 5}, expected_locals={"z": 1})
    run_test("IF (False branch, x=15)", code_if, initial_values={"x": 15}, expected_locals={"z": 2})
    run_test(
        "IF Symbolic (x < 10, x=5)",
        code_if,
        symbolic_vars={"x": "int"},
        initial_values={"x": 5},
        expected_locals={"z": 1},
    )

    code_if_not = """
if not (x < 10):
    z = 1
else:
    z = 2
"""
    run_test(
        "IF NOT (True branch, x=15)",
        code_if_not,
        initial_values={"x": 15},
        expected_locals={"z": 1},
    )
    run_test(
        "IF NOT (False branch, x=5)", code_if_not, initial_values={"x": 5}, expected_locals={"z": 2}
    )

    code_while = """
i = 0
z = 0
while i < 3:
    z += x
    i += 1
"""
    run_test(
        "WHILE (3 iterations, x=10)",
        code_while,
        initial_values={"x": 10},
        expected_locals={"z": 30},
    )


def validate_iteration():
    print("\n--- Validating Iteration Opcodes ---")

    code_for = """
z = 0
for i in [1, 2, 3]:
    z += i
"""
    run_test("FOR (List [1, 2, 3])", code_for, expected_locals={"z": 6})

    code_for_empty = """
z = 0
for i in []:
    z += 1
"""
    run_test("FOR (Empty List)", code_for_empty, expected_locals={"z": 0})


if __name__ == "__main__":
    validate_comparisons()
    validate_control_flow()
    validate_iteration()
