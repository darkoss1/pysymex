import sys
from functools import lru_cache

from pysymex._internal.config.sandbox.bridge import make_sandbox_config
from pysymex._internal.sandbox.errors import SandboxSetupError
from pysymex._internal.sandbox.runner import SecureSandbox


def live_sandbox_backend_config() -> dict[str, object]:
    if sys.platform == "win32":
        return {"backend": "WINDOWS_APPCONTAINER"}
    if sys.platform == "linux":
        return {"backend": "LINUX_NAMESPACE"}
    return {}


def _linux_namespace_unavailable(message: str) -> bool:
    if sys.platform != "linux" or "unshare" not in message:
        return False
    return "Operation not permitted" in message or "Resource temporarily unavailable" in message


@lru_cache(maxsize=1)
def live_sandbox_skip_reason() -> str | None:
    config = make_sandbox_config(live_sandbox_backend_config())
    try:
        with SecureSandbox(config) as sandbox:
            result = sandbox.execute_code(
                "print('__pysymex_sandbox_smoke__')",
                filename="sandbox_smoke.py",
            )
    except SandboxSetupError as exc:
        return f"real sandbox backend is unavailable: {exc}"

    if result.succeeded:
        return None

    stderr = result.get_stderr_text()
    message = result.error_message or stderr or result.get_stdout_text()
    if _linux_namespace_unavailable(message):
        return f"Linux namespace sandbox is unavailable in this runner: {message}"
    raise AssertionError(f"real sandbox smoke test failed: {message}")
