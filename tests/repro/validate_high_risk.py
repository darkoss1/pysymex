import sys
import os
import dis

# Add the project root to sys.path to allow imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

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


def validate_stack_locals():
    print("\n--- Validating Stack & Local Opcodes ---")

    run_test(
        "POP_TOP", "x = 1; y = 2; x", initial_values={"x": 1, "y": 2}, expected_locals={"x": 1}
    )
    run_test("DUP_TOP", "x = 1; y = x", expected_locals={"y": 1})

    run_test("STORE_FAST / LOAD_FAST", "x = 10; y = x", expected_locals={"y": 10})
    run_test("DELETE_FAST", "x = 10; del x", expected_locals={})

    run_test("STORE_GLOBAL", "global x; x = 20", expected_locals={"x": 20})


def validate_collections():
    print("\n--- Validating Collection Opcodes ---")

    run_test("BUILD_LIST", "x = [1, 2, 3]", expected_locals={"x": [1, 2, 3]})
    run_test("BUILD_MAP", "x = {'a': 1, 'b': 2}", expected_locals={"x": {"a": 1, "b": 2}})

    run_test("BINARY_SUBSCR (List)", "l = [10, 20]; x = l[1]", expected_locals={"x": 20})
    run_test("BINARY_SUBSCR (Dict)", "d = {'a': 100}; x = d['a']", expected_locals={"x": 100})

    run_test("STORE_SUBSCR (List)", "l = [10, 20]; l[0] = 30; x = l[0]", expected_locals={"x": 30})


def validate_functions_exceptions():
    print("\n--- Validating Functions & Exceptions ---")

    code_call = """
def add(a, b):
    return a + b
x = add(1, 2)
"""
    run_test("CALL Concrete", code_call, expected_locals={"x": 3})

    code_call_sym = """
def add(a, b):
    return a + b
x = add(a_val, 5)
"""
    run_test(
        "CALL Symbolic",
        code_call_sym,
        symbolic_vars={"a_val": "int"},
        initial_values={"a_val": 10},
        expected_locals={"x": 15},
    )

    code_exc = """
try:
    x = 1 / 0
except ZeroDivisionError:
    z = 1
else:
    z = 2
"""
    run_test("Exception Handling (ZeroDivisionError)", code_exc, expected_locals={"z": 1})


if __name__ == "__main__":
    validate_stack_locals()
    validate_collections()
    validate_functions_exceptions()
