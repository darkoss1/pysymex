import pytest
from pysymex.sandbox.isolation.harness import HARNESS_FILENAME, generate_harness_script


@pytest.mark.timeout(30)
def test_generate_harness_script() -> None:
    """Test generate_harness_script behavior."""
    script = generate_harness_script(
        blocked_modules=frozenset({"os", "socket"}),
        allowed_imports=frozenset({"math"}),
        dangerous_builtins=frozenset({"open", "eval"}),
        suspicious_patterns=("__globals__",),
        restrict_builtins=True,
        enable_ast_prescreening=True,
        install_audit_hook=True,
        block_ast_imports=True,
        install_seccomp=True,
        seccomp_allowlist=(0, 1, 60),
    )

    assert HARNESS_FILENAME == "_sandbox_harness.py"
    assert "_sandbox_harness.py" in script
    assert "sandbox-harness: invalid target filename" in script
    assert "sandbox-harness: illegal characters in filename" in script
    assert "_BLOCKED" in script
    assert "socket" in script
    assert "os" in script
    assert "_ALLOWED_IMPORTS" in script
    assert "math" in script
    assert "_DANGEROUS_BUILTINS" in script
    assert "open" in script
    assert "eval" in script
    assert "_ENABLE_AST_PRESCREENING" in script
    assert "_BLOCK_AST_IMPORTS" in script
    assert "sandbox-harness: rejected" in script
    assert "_INSTALL_AUDIT_HOOK" in script
    assert "_INSTALL_SECCOMP" in script
    assert "_SECCOMP_ALLOWLIST" in script
    assert "exec(_code_obj, _namespace)" in script
