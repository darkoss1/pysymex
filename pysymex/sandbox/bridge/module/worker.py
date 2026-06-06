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

"""Build the sandbox module-extraction worker source."""

from __future__ import annotations

import textwrap

from pysymex.sandbox.bridge.module.contracts import module_contract_source
from pysymex.sandbox.bridge.module.serializers import module_serializer_source
from pysymex.sandbox.bridge.types import EXTRACTION_SCHEMA_VERSION


def build_module_worker(
    *,
    dynamic_marker: str,
    filename: str,
) -> str:
    """Build worker source for sandboxed module extraction.

    Args:
        dynamic_marker: Unique line prefix used for the worker result envelope.
        filename: Filename used when compiling target source from standard
            input.

    Returns:
        Python source that executes the target module, serializes supported
        functions and contract metadata, records unsupported-target
        diagnostics, and emits a JSON envelope.

    Side Effects:
        The returned source executes module initialization when it is later
        run by the sandbox worker.

    Limitations:
        The generated worker provides contract-compatible import stand-ins but
        does not itself apply a general target import allowlist or blocklist.
    """
    contracts = module_contract_source()
    serializers = module_serializer_source()
    header = textwrap.dedent(
        f"""
        import base64
        import builtins
        import json
        import sys
        import traceback
        import types

        _MARKER = {dynamic_marker!r}
        _FILENAME = {filename!r}
        _IMPORT_ATTR = "__" + "import__"
        _GLOBALS_ATTR = "__" + "globals__"
        _BUILTINS_KEY = "__" + "builtins__"

        def _emit(payload):
            print(_MARKER + json.dumps(payload, ensure_ascii=True, separators=(",", ":")))
        """
    ).strip()
    body = textwrap.dedent(
        f"""
        try:
            _source = sys.stdin.buffer.read()
            _module_code = compile(_source, _FILENAME, "exec")
            _namespace = {{
                _BUILTINS_KEY: _target_builtins(),
                "__name__": "__pysymex_target__",
                "__file__": _FILENAME,
            }}
            exec(_module_code, _namespace)
            _targets = {{}}
            _diagnostics = []
            for _name, _func in _iter_function_targets(_namespace):
                try:
                    _targets[_name] = _serialize_function_target(_func)
                except TypeError as _target_exc:
                    _diagnostics.append(
                        {{
                            "level": "WARNING",
                            "message": (
                                f"target '{{_name}}' was not serialized: {{type(_target_exc).__name__}}: "
                                f"{{_target_exc}}"
                            ),
                        }}
                    )
            _emit({{
                "ok": True,
                "payload": {{
                    "schema_version": {EXTRACTION_SCHEMA_VERSION!r},
                    "kind": "pysymex.module",
                    "producer": {{
                        "python_implementation": sys.implementation.name,
                        "python_version": [
                            sys.version_info.major,
                            sys.version_info.minor,
                            sys.version_info.micro,
                        ],
                    }},
                    "module": _serialize_code(_module_code),
                    "targets": _targets,
                    "diagnostics": _diagnostics,
                }},
            }})
        except Exception as _exc:
            _emit(
                {{
                    "ok": False,
                    "error": f"{{type(_exc).__name__}}: {{_exc}}",
                    "traceback": traceback.format_exc(),
                }}
            )
        """
    ).strip()
    return "\n\n".join((header, contracts, serializers, body))
