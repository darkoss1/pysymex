import pytest
from pysymex.sandbox.isolation.constants import HARNESS_FILENAME as CANONICAL_HARNESS_FILENAME
from pysymex.sandbox.isolation.harness import HARNESS_FILENAME, generate_harness_script


def test_harness_filename_public_import() -> None:
    """Public and canonical harness filename imports refer to the same value."""
    assert HARNESS_FILENAME == CANONICAL_HARNESS_FILENAME


@pytest.mark.timeout(30)
def test_generate_harness_script() -> None:
    """Generated harness validates filename, compiles, and executes without Python policy."""
    script = generate_harness_script()

    assert HARNESS_FILENAME == "_sandbox_harness.py"
    assert "_sandbox_harness.py" in script
    assert "sandbox-harness: invalid target filename" in script
    assert "sandbox-harness: illegal characters in filename" in script
    assert "PYSYMEX_SANDBOX_JAIL" in script
    assert "_target_name" in script
    assert "_target_builtins" in script
    assert 'compile(_source, _target, "exec")' in script
    assert "exec(_code_obj, _namespace)" in script
    assert "_AUDIT_BLOCKED_PREFIXES" not in script
    assert "_BLOCKED" not in script
    assert "_DANGEROUS_BUILTINS" not in script
    assert "addaudithook" not in script
