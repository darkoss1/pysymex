import json
import re
from types import CodeType
from typing import TypeGuard

from pysymex.sandbox.bridge.types import create_bytecode_payload


def is_object_mapping(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict)


def create_bridge_payload(code_obj: CodeType, filename: str) -> bytes:
    _ = filename
    return create_bytecode_payload(code_obj)


def create_module_payload(
    code_obj: CodeType,
    targets: dict[str, object],
    diagnostics: list[object] | None = None,
) -> bytes:
    payload = json.loads(create_bytecode_payload(code_obj, diagnostics=diagnostics).decode("utf-8"))
    assert is_object_mapping(payload)
    payload["kind"] = "pysymex.module"
    payload["targets"] = targets
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def make_function_from_source(source: str, filename: str, name: str) -> object:
    namespace: dict[str, object] = {}
    exec(compile(source, filename, "exec"), namespace)
    return namespace[name]


def extract_json_worker_marker(worker_script: str) -> str:
    marker_match = re.search(r"_MARKER = '([^']+)'", worker_script)
    assert marker_match is not None
    return marker_match.group(1)
