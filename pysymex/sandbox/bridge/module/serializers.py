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

from __future__ import annotations

import textwrap

_SERIALIZER_SOURCE_TEMPLATE = r"""        def _serialize_code(co):
            def _serialize_const(value):
                if isinstance(value, type(co)):
                    return _serialize_code(value)
                if isinstance(value, tuple):
                    return {{"kind": "tuple", "items": [_serialize_const(item) for item in value]}}
                if isinstance(value, frozenset):
                    return {{
                        "kind": "frozenset",
                        "items": [_serialize_const(item) for item in value],
                    }}
                if isinstance(value, bytes):
                    return {{"kind": "bytes", "data": base64.b64encode(value).decode("ascii")}}
                if isinstance(value, (int, float, str, type(None), bool)):
                    return value
                raise TypeError(f"unsupported constant type: {{type(value).__name__}}")

            return {{
                "kind": "code",
                "argcount": co.co_argcount,
                "posonlyargcount": getattr(co, "co_posonlyargcount", 0),
                "kwonlyargcount": co.co_kwonlyargcount,
                "nlocals": co.co_nlocals,
                "stacksize": co.co_stacksize,
                "flags": co.co_flags,
                "code": base64.b64encode(co.co_code).decode("ascii"),
                "consts": [_serialize_const(value) for value in co.co_consts],
                "names": list(co.co_names),
                "varnames": list(co.co_varnames),
                "freevars": list(getattr(co, "co_freevars", ())),
                "cellvars": list(getattr(co, "co_cellvars", ())),
                "filename": co.co_filename,
                "name": co.co_name,
                "qualname": getattr(co, "co_qualname", co.co_name),
                "firstlineno": co.co_firstlineno,
                "linetable": base64.b64encode(getattr(co, "co_linetable", b"")).decode("ascii"),
                "exceptiontable": base64.b64encode(
                    getattr(co, "co_exceptiontable", b"")
                ).decode("ascii"),
            }}

        def _serialize_const(value):
            if isinstance(value, types.CodeType):
                return _serialize_code(value)
            if isinstance(value, tuple):
                return {{"kind": "tuple", "items": [_serialize_const(item) for item in value]}}
            if isinstance(value, frozenset):
                return {{"kind": "frozenset", "items": [_serialize_const(item) for item in value]}}
            if isinstance(value, bytes):
                return {{"kind": "bytes", "data": base64.b64encode(value).decode("ascii")}}
            if isinstance(value, (int, float, str, type(None), bool)):
                return value
            raise TypeError(f"unsupported value type: {{type(value).__name__}}")

        def _serialize_annotation(value):
            if isinstance(value, type):
                return value.__qualname__
            return _serialize_const(value)

        def _serialize_contract_clause(clause):
            predicate = getattr(clause, "predicate", None)
            if isinstance(predicate, str):
                predicate_kind = "string"
                serialized_predicate = predicate
            else:
                predicate_kind = "unsupported_callable"
                serialized_predicate = None
            kind = getattr(getattr(clause, "kind", None), "name", "")
            severity = getattr(getattr(clause, "severity", None), "name", "ERROR")
            condition = str(getattr(clause, "condition", ""))
            message = str(getattr(clause, "message", ""))
            line_number = getattr(clause, "line_number", None)
            if not isinstance(line_number, int):
                line_number = None
            return {{
                "kind": kind,
                "predicate_kind": predicate_kind,
                "predicate": serialized_predicate,
                "condition": condition,
                "message": message,
                "severity": severity,
                "line_number": line_number,
            }}

        def _serialize_function_contract(func):
            contract = getattr(func, "__contract__", None)
            if contract is None:
                return None
            return {{
                "function_name": str(getattr(contract, "function_name", func.__name__)),
                "preconditions": [
                    _serialize_contract_clause(clause)
                    for clause in getattr(contract, "preconditions", [])
                ],
                "postconditions": [
                    _serialize_contract_clause(clause)
                    for clause in getattr(contract, "postconditions", [])
                ],
            }}

        def _serialize_function_target(func):
            globals_payload = {{}}
            func_globals = getattr(func, _GLOBALS_ATTR)
            for name in func.__code__.co_names:
                if name == func.__name__ and func_globals.get(name) is func:
                    continue
                if name in func_globals:
                    value = func_globals[name]
                    try:
                        globals_payload[name] = _serialize_const(value)
                    except TypeError as exc:
                        raise TypeError(
                            f"unsupported global '{{name}}' required by target function"
                        ) from exc

            closure_payload = None
            if func.__closure__ is not None:
                closure_payload = [_serialize_const(cell.cell_contents) for cell in func.__closure__]

            return {{
                "kind": "function",
                "name": func.__name__,
                "qualname": func.__qualname__,
                "module": str(func.__module__),
                "code": _serialize_code(func.__code__),
                "defaults": None
                if func.__defaults__ is None
                else [_serialize_const(value) for value in func.__defaults__],
                "kwdefaults": None
                if func.__kwdefaults__ is None
                else {{
                    key: _serialize_const(value)
                    for key, value in func.__kwdefaults__.items()
                }},
                "annotations": {{
                    key: _serialize_annotation(value)
                    for key, value in func.__annotations__.items()
                }},
                "closure": closure_payload,
                "globals": globals_payload,
                "contract": _serialize_function_contract(func),
                "diagnostics": [],
            }}

        def _iter_function_targets(namespace):
            for name, value in sorted(namespace.items()):
                if name.startswith("__"):
                    continue
                if (
                    isinstance(value, types.FunctionType)
                    and getattr(value, _GLOBALS_ATTR, None) is namespace
                ):
                    yield name, value
                    continue
                if isinstance(value, type):
                    for attr_name, raw in sorted(vars(value).items()):
                        if attr_name.startswith("__"):
                            continue
                        func = None
                        if isinstance(raw, (staticmethod, classmethod)):
                            candidate = raw.__func__
                            if isinstance(candidate, types.FunctionType):
                                func = candidate
                        elif isinstance(raw, types.FunctionType):
                            func = raw
                        if func is not None and getattr(func, _GLOBALS_ATTR, None) is namespace:
                            yield f"{{name}}.{{attr_name}}", func
"""


def module_serializer_source() -> str:
    """Render serializer helpers embedded in module extraction workers.

    Returns:
        Python source that serializes supported code objects, constants,
        contract metadata, and target functions found in a worker namespace.

    Limitations:
        Generated serializers reject unsupported globals, constants, and
        closure values instead of executing arbitrary serialization hooks.
    """
    return (
        textwrap.dedent(_SERIALIZER_SOURCE_TEMPLATE).strip().replace("{{", "{").replace("}}", "}")
    )
