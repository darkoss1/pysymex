import os
import sys

# Add the project root to sys.path to allow imports.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from tests.repro.arithmetic_validation_cases import ARITHMETIC_CASES
from tests.repro.opcode_validator import validate_opcode


def run_tests() -> None:
    findings: list[str] = []

    for validation_case in ARITHMETIC_CASES:
        success, message = validate_opcode(
            validation_case.source,
            symbolic_vars=validation_case.symbolic_vars,
            initial_values=validation_case.initial_values,
            expected_locals=validation_case.expected_locals,
            description=validation_case.description,
        )
        if not success:
            findings.append(message)

    if not findings:
        print("All arithmetic opcodes passed validation.")
    else:
        for finding in findings:
            print(finding)


if __name__ == "__main__":
    run_tests()
