import unittest
from pysymex.sandbox import SecureSandbox, SandboxBackend, SandboxConfig

class TestSandboxIsolation(unittest.TestCase):
    def test_create_file_inside_jail_works(self):
        """Verify the sandbox allows writing to its own ephemeral jail."""
        config = SandboxConfig(
            backend=SandboxBackend.SUBPROCESS,
            allow_weak_backends=True,
            harness_restrict_builtins=False,
            harness_block_ast_imports=False,
        )
        code = b"with open('test_file.txt', 'w') as f: f.write('success')"
        with SecureSandbox(config) as sandbox:
            result = sandbox.execute_code(code, filename="test_writer.py")
            self.assertTrue(result.succeeded, f"Execution failed: {result.stderr}")
            # The sandbox result doesn't automatically return the file,
            # but we can verify it was created if we check the jail path 
            # or if the execution itself confirmed success.
            # Here we just verify the code finished.

    def test_attempt_access_host_file_fails(self):
        """Verify the sandbox blocks writing to host filesystem."""
        # Attempt to write to a path outside the jail
        code = b"with open('C:/Windows/temp/exploit.txt', 'w') as f: f.write('exploit')"
        config = SandboxConfig(
            backend=SandboxBackend.SUBPROCESS,
            allow_weak_backends=True,
            harness_restrict_builtins=False,
            harness_block_ast_imports=False,
        )
        with SecureSandbox(config) as sandbox:
            result = sandbox.execute_code(code, filename="test_exploit.py")
            # Should fail due to security policy (audit hook)
            self.assertFalse(result.succeeded, "Sandbox allowed write outside jail!")
            self.assertIn("blocked", result.get_stderr_text().lower())

if __name__ == '__main__':
    unittest.main()
