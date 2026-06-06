import socket
from pathlib import Path

import pytest

from pysymex.sandbox.errors import SandboxSetupError
from pysymex.sandbox.types import ExecutionStatus, ResourceLimits, SandboxConfig
from tests.unit.sandbox.isolation.windows_appcontainer_helpers import (
    InspectableWindowsAppContainerBackend,
    has_live_appcontainer_support,
)


class TestWindowsAppContainerBackend:
    @pytest.mark.timeout(60)
    @pytest.mark.skipif(
        not has_live_appcontainer_support(),
        reason="Windows AppContainer APIs are unavailable",
    )
    def test_live_appcontainer_fails_closed_or_blocks_hostile_operations(
        self,
        tmp_path: Path,
    ) -> None:
        import os
        import time
        import winreg

        secret_path = tmp_path / "host_secret.txt"
        secret_path.write_text("host secret", encoding="utf-8")
        registry_probe_key = f"Software\\pysymex_test_probe_{os.getpid()}_{time.time_ns()}"
        registry_probe_value = "secret"
        registry_probe_secret = "pysymex-host-registry-secret"
        key = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            registry_probe_key,
            0,
            winreg.KEY_SET_VALUE,
        )
        try:
            winreg.SetValueEx(
                key,
                registry_probe_value,
                0,
                winreg.REG_SZ,
                registry_probe_secret,
            )
        finally:
            winreg.CloseKey(key)

        backend = InspectableWindowsAppContainerBackend(
            SandboxConfig(
                environment={
                    "PYSYMEX_SECRET_TOKEN": "must-not-leak",
                    "CUSTOM_FLAG": "must-not-leak",
                },
                limits=ResourceLimits(timeout_seconds=10),
            )
        )
        try:
            try:
                backend.setup()
            except SandboxSetupError as exc:
                message = str(exc)
                assert (
                    "Windows AppContainer self-check failed" in message
                    or "Windows AppContainer security self-check failed" in message
                    or "network-deny" in message
                    or "registry-deny" in message
                    or "AppContainer SID" in message
                    or "unexpected AppContainer capabilities" in message
                    or "unexpected AppContainer capability count" in message
                )
                return
            status, exit_code, stdout, stderr, _, _ = backend.run_raw_python_for_test(
                (
                    "import os, pathlib, subprocess, sys\n"
                    f"secret_path = pathlib.Path({str(secret_path)!r})\n"
                    "checks = []\n"
                    "if pathlib.Path.cwd() == pathlib.Path(os.environ['PYTHONHOME']):\n"
                    "    checks.append('runtime-cwd')\n"
                    "try:\n"
                    "    secret_path.read_text(encoding='utf-8')\n"
                    "except Exception:\n"
                    "    checks.append('file-denied')\n"
                    "if 'PYSYMEX_SECRET_TOKEN' not in os.environ:\n"
                    "    checks.append('env-denied')\n"
                    "if 'CUSTOM_FLAG' not in os.environ:\n"
                    "    checks.append('custom-env-denied')\n"
                    "try:\n"
                    "    subprocess.run([sys.executable, '-c', 'pass'], timeout=5)\n"
                    "except Exception:\n"
                    "    checks.append('subprocess-denied')\n"
                    "try:\n"
                    "    completed = subprocess.run(['cmd.exe', '/c', 'exit', '0'], timeout=5)\n"
                    "except Exception:\n"
                    "    checks.append('cmd-denied')\n"
                    "else:\n"
                    "    if completed.returncode != 0:\n"
                    "        checks.append('cmd-denied')\n"
                    "try:\n"
                    "    completed = subprocess.run(\n"
                    "        ['powershell.exe', '-NoProfile', '-Command', 'exit'], timeout=5\n"
                    "    )\n"
                    "except Exception:\n"
                    "    checks.append('powershell-denied')\n"
                    "else:\n"
                    "    if completed.returncode != 0:\n"
                    "        checks.append('powershell-denied')\n"
                    "try:\n"
                    "    rc = os.system('cmd.exe /c exit 0')\n"
                    "except Exception:\n"
                    "    checks.append('os-system-denied')\n"
                    "else:\n"
                    "    if rc != 0:\n"
                    "        checks.append('os-system-denied')\n"
                    "try:\n"
                    "    import ctypes\n"
                    "except Exception:\n"
                    "    checks.append('ctypes-denied')\n"
                    "try:\n"
                    "    import winreg\n"
                    f"    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, {registry_probe_key!r})\n"
                    f"    value, _ = winreg.QueryValueEx(key, {registry_probe_value!r})\n"
                    "    winreg.CloseKey(key)\n"
                    "except Exception:\n"
                    "    checks.append('registry-denied')\n"
                    f"else:\n"
                    f"    if value != {registry_probe_secret!r}:\n"
                    "        checks.append('registry-denied')\n"
                    "print(','.join(sorted(checks)))\n"
                    "sys.exit(0 if len(checks) == 10 else 91)\n"
                )
            )
            assert status is ExecutionStatus.SUCCESS
            assert exit_code == 0
            assert stderr == b""
            assert b"env-denied" in stdout
            assert b"custom-env-denied" in stdout
            assert b"file-denied" in stdout
            assert b"cmd-denied" in stdout
            assert b"os-system-denied" in stdout
            assert b"powershell-denied" in stdout
            assert b"runtime-cwd" in stdout
            assert b"subprocess-denied" in stdout
            assert b"ctypes-denied" in stdout
            assert b"registry-denied" in stdout

            status, exit_code, stdout, stderr, _, _ = backend.run_raw_python_for_test(
                (
                    "import os, pathlib, sys\n"
                    "runtime = pathlib.Path(os.environ['PYTHONHOME'])\n"
                    "checks = []\n"
                    "write_probe = runtime / '_pysymex_live_runtime_write_probe.txt'\n"
                    "try:\n"
                    "    write_probe.write_text('escape', encoding='utf-8')\n"
                    "except Exception:\n"
                    "    checks.append('runtime-write-denied')\n"
                    "else:\n"
                    "    try:\n"
                    "        write_probe.unlink()\n"
                    "    except Exception:\n"
                    "        pass\n"
                    "manifest = runtime / '.pysymex-runtime-manifest.json'\n"
                    "try:\n"
                    "    manifest.unlink()\n"
                    "except Exception:\n"
                    "    checks.append('runtime-delete-denied')\n"
                    "lib = runtime / 'Lib'\n"
                    "renamed = runtime / '_pysymex_live_runtime_renamed'\n"
                    "try:\n"
                    "    lib.rename(renamed)\n"
                    "except Exception:\n"
                    "    checks.append('runtime-rename-denied')\n"
                    "else:\n"
                    "    try:\n"
                    "        renamed.rename(lib)\n"
                    "    except Exception:\n"
                    "        pass\n"
                    "print(','.join(sorted(checks)))\n"
                    "sys.exit(0 if len(checks) == 3 else 93)\n"
                )
            )
            assert status is ExecutionStatus.SUCCESS
            assert exit_code == 0
            assert stdout.strip() == (
                b"runtime-delete-denied,runtime-rename-denied,runtime-write-denied"
            )
            assert stderr == b""

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                host, port = listener.getsockname()
                status, exit_code, stdout, stderr, _, _ = backend.run_raw_python_for_test(
                    (
                        "import sys\n"
                        f"address = ({host!r}, {int(port)!r})\n"
                        "checks = []\n"
                        "try:\n"
                        "    import socket\n"
                        "    with socket.create_connection(address, timeout=1.0):\n"
                        "        pass\n"
                        "except Exception:\n"
                        "    checks.append('socket-denied')\n"
                        "try:\n"
                        "    import urllib.request\n"
                        f"    urllib.request.urlopen('http://{host}:{int(port)}/', timeout=1).close()\n"
                        "except Exception:\n"
                        "    checks.append('urllib-denied')\n"
                        "try:\n"
                        "    import http.client\n"
                        f"    conn = http.client.HTTPConnection({host!r}, {int(port)}, timeout=1)\n"
                        "    conn.connect()\n"
                        "except Exception:\n"
                        "    checks.append('httpclient-denied')\n"
                        "try:\n"
                        "    import asyncio\n"
                        "    async def main():\n"
                        "        reader, writer = await asyncio.open_connection(*address)\n"
                        "        writer.close()\n"
                        "        await writer.wait_closed()\n"
                        "    asyncio.run(main())\n"
                        "except Exception:\n"
                        "    checks.append('asyncio-denied')\n"
                        "print(','.join(sorted(checks)))\n"
                        "sys.exit(0 if len(checks) == 4 else 92)\n"
                    )
                )
            assert status is ExecutionStatus.SUCCESS
            assert exit_code == 0
            assert b"asyncio-denied" in stdout
            assert b"httpclient-denied" in stdout
            assert b"socket-denied" in stdout
            assert b"urllib-denied" in stdout
            assert stderr == b""
        finally:
            backend.cleanup()
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_probe_key)
            except OSError:
                pass
