"""Test exports of pysymex.analysis.contracts.__init__."""

import pysymex.analysis.contracts as c


def test_has_exports() -> None:
    """Test that contract types are exported."""
    exports = [
        "Contract",
        "ContractCompiler",
        "ContractKind",
        "ContractVerifier",
        "ContractViolation",
        "FunctionContract",
        "VerificationReport",
        "VerificationResult",
        "ensures",
        "function_contracts",
        "get_function_contract",
        "invariant",
        "loop_invariant",
        "requires",
    ]
    for export in exports:
        assert hasattr(c, export)
