# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Child-process source generation for AppContainer self-check probes."""

from __future__ import annotations

from pysymex._internal.sandbox.isolation.windows.appcontainer.shared import (
    RUNTIME_MANIFEST_FILENAME,
)


def build_combined_self_check_code(
    *,
    expected_profile: str,
    expected_pythonhome: str,
    denied_file: str,
    lpac_probe_file: str,
    registry_probe_key: str,
    registry_probe_value: str,
    registry_probe_secret: str,
    network_host: str,
    network_port: int,
) -> str:
    """Construct the Python source used for the combined AppContainer self-check."""
    return (
        "import importlib, json, os, pathlib, subprocess, sys\n"
        "checks = []\n"
        "failures = []\n"
        f"if os.environ.get('USERPROFILE') == {expected_profile!r} "
        f"and os.environ.get('PYTHONHOME') == {expected_pythonhome!r}:\n"
        "    checks.append('launch-boundary')\n"
        "else:\n"
        "    failures.append('launch-boundary')\n"
        f"runtime = pathlib.Path({expected_pythonhome!r})\n"
        "runtime_write_path = runtime / '_pysymex_runtime_write_probe.txt'\n"
        "try:\n"
        "    runtime_write_path.write_text('escape', encoding='utf-8')\n"
        "except Exception:\n"
        "    checks.append('runtime-write-deny')\n"
        "else:\n"
        "    failures.append('runtime-write-deny')\n"
        "    try:\n"
        "        runtime_write_path.unlink()\n"
        "    except Exception:\n"
        "        pass\n"
        f"runtime_manifest_path = runtime / {RUNTIME_MANIFEST_FILENAME!r}\n"
        "if not runtime_manifest_path.exists():\n"
        "    failures.append('runtime-delete-deny:missing')\n"
        "else:\n"
        "    try:\n"
        "        runtime_manifest_path.unlink()\n"
        "    except Exception:\n"
        "        checks.append('runtime-delete-deny')\n"
        "    else:\n"
        "        failures.append('runtime-delete-deny')\n"
        "runtime_lib_path = runtime / 'Lib'\n"
        "runtime_rename_path = runtime / '_pysymex_runtime_renamed'\n"
        "if not runtime_lib_path.exists():\n"
        "    failures.append('runtime-rename-deny:missing')\n"
        "else:\n"
        "    try:\n"
        "        runtime_lib_path.rename(runtime_rename_path)\n"
        "    except Exception:\n"
        "        checks.append('runtime-rename-deny')\n"
        "    else:\n"
        "        failures.append('runtime-rename-deny')\n"
        "        try:\n"
        "            runtime_rename_path.rename(runtime_lib_path)\n"
        "        except Exception:\n"
        "            pass\n"
        "blocked_env = ('KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'CREDENTIAL')\n"
        "if any(any(part in key.upper() for part in blocked_env) for key in os.environ):\n"
        "    failures.append('environment-deny')\n"
        "else:\n"
        "    checks.append('environment-deny')\n"
        f"path = pathlib.Path({denied_file!r})\n"
        "try:\n"
        "    path.read_text(encoding='utf-8')\n"
        "except Exception:\n"
        "    checks.append('filesystem-deny')\n"
        "else:\n"
        "    failures.append('filesystem-deny')\n"
        f"lpac_probe_path = pathlib.Path({lpac_probe_file!r})\n"
        "try:\n"
        "    lpac_probe_path.read_text(encoding='utf-8')\n"
        "except Exception:\n"
        "    checks.append('lpac-deny')\n"
        "else:\n"
        "    failures.append('lpac-deny')\n"
        "native_modules = ('_ctypes', 'ctypes', '_socket', '_winreg')\n"
        "native_escapes = []\n"
        "for name in native_modules:\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "    except Exception:\n"
        "        continue\n"
        "    native_escapes.append(name)\n"
        "if native_escapes:\n"
        "    failures.append('native-extension-deny:' + ','.join(native_escapes))\n"
        "else:\n"
        "    checks.append('native-extension-deny')\n"
        "try:\n"
        "    import winreg\n"
        f"    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, {registry_probe_key!r})\n"
        f"    value, _ = winreg.QueryValueEx(key, {registry_probe_value!r})\n"
        "    winreg.CloseKey(key)\n"
        "except Exception:\n"
        "    checks.append('registry-deny')\n"
        "else:\n"
        f"    if value == {registry_probe_secret!r}:\n"
        "        failures.append('registry-deny')\n"
        "    else:\n"
        "        checks.append('registry-deny')\n"
        "try:\n"
        "    completed = subprocess.run([sys.executable, '-c', 'pass'], timeout=5)\n"
        "except Exception:\n"
        "    checks.append('subprocess-deny')\n"
        "else:\n"
        "    if completed.returncode == 0:\n"
        "        failures.append('subprocess-deny')\n"
        "    else:\n"
        "        checks.append('subprocess-deny')\n"
        "try:\n"
        "    import socket\n"
        f"    with socket.create_connection(({network_host!r}, {network_port!r}), timeout=1.0):\n"
        "        pass\n"
        "except Exception:\n"
        "    checks.append('network-deny')\n"
        "else:\n"
        "    failures.append('network-deny')\n"
        "expected = {\n"
        "    'launch-boundary',\n"
        "    'runtime-write-deny',\n"
        "    'runtime-delete-deny',\n"
        "    'runtime-rename-deny',\n"
        "    'environment-deny',\n"
        "    'filesystem-deny',\n"
        "    'lpac-deny',\n"
        "    'native-extension-deny',\n"
        "    'registry-deny',\n"
        "    'subprocess-deny',\n"
        "    'network-deny',\n"
        "}\n"
        "missing = sorted(expected - set(checks))\n"
        "print(json.dumps({'checks': sorted(checks), 'failures': failures, 'missing': missing}))\n"
        "sys.exit(0 if not failures and not missing else 90)\n"
    )
