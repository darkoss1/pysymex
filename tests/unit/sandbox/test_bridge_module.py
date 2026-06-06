import json
from functools import lru_cache
from unittest.mock import patch

import pytest

from pysymex.sandbox.errors import SandboxProtocolError
from pysymex.sandbox.bridge.cache import clear_module_extraction_cache, module_cache_key
from pysymex.sandbox.bridge.module import extract_module
from pysymex.sandbox.bridge.module.worker import build_module_worker
from pysymex.sandbox.bridge.types import FunctionBlob, ModuleBlob, create_function_payload
from pysymex.utils.hashing import stable_digest_hex
from tests.unit.sandbox.bridge_test_helpers import (
    create_module_payload,
    is_object_mapping,
    make_function_from_source,
)
from tests.unit.sandbox.live_sandbox_helpers import (
    live_sandbox_backend_config,
    live_sandbox_skip_reason,
)


@lru_cache(maxsize=1)
def _real_worker_skip_reason() -> str | None:
    return live_sandbox_skip_reason()


def _real_worker_sandbox_config() -> dict[str, object]:
    reason = _real_worker_skip_reason()
    if reason is not None:
        pytest.skip(reason)
    return live_sandbox_backend_config()


@pytest.mark.timeout(30)
def test_module_worker_does_not_filter_target_imports() -> None:
    """AppContainer is the sandbox boundary; module extraction should not filter imports."""
    worker = build_module_worker(dynamic_marker="MARKER", filename="target.py")

    assert "_contract_aware_import" in worker
    assert "_ALLOWED_IMPORTS" not in worker
    assert "_BLOCKED_MODULES" not in worker
    assert "not allowlisted during sandbox extraction" not in worker
    assert "blocked during sandbox extraction" not in worker


@pytest.mark.timeout(30)
def test_extract_module_reconstructs_sanitized_function_payload() -> None:
    """Target extraction returns a host function without returning a live sandbox object."""
    filename = "target.py"
    func_obj = make_function_from_source(
        "def target(x: int, step: int = 1) -> int:\n    return x + step\n",
        filename,
        "target",
    )
    assert callable(func_obj)
    function_payload = json.loads(create_function_payload(func_obj, target_name="target").decode())
    assert is_object_mapping(function_payload)
    module_code = compile(
        "def target(x: int, step: int = 1) -> int:\n    return x + step\n", filename, "exec"
    )
    payload = create_module_payload(module_code, {"target": function_payload["target"]})

    def mock_run_json_worker(
        worker_script: str, **kwargs: object
    ) -> tuple[dict[str, object], str, str]:
        _ = worker_script
        sandbox_cfg = kwargs.get("sandbox_config")
        assert is_object_mapping(sandbox_cfg)
        assert "harness_install_audit_hook" not in sandbox_cfg
        assert "harness_allowed_imports" not in sandbox_cfg
        assert "harness_blocked_modules" not in sandbox_cfg
        return ({"ok": True, "payload": json.loads(payload.decode("utf-8"))}, "", "")

    with patch("pysymex.sandbox.bridge.module._run_json_worker", side_effect=mock_run_json_worker):
        module_blob = extract_module(b"raise RuntimeError('host must not execute this')", filename)
        blob = module_blob.get_function_blob("target")

    assert isinstance(blob, FunctionBlob)
    rebuilt = blob.reconstruct()
    assert rebuilt.__name__ == "target"
    assert rebuilt.__defaults__ == (1,)
    assert rebuilt.__code__.co_filename == filename


@pytest.mark.timeout(30)
def test_extract_module_returns_reusable_function_payloads() -> None:
    """One sandbox module extraction payload can reconstruct multiple functions."""
    filename = "target.py"
    module_code = compile(
        "def first():\n    return 1\n\ndef second():\n    return 2\n", filename, "exec"
    )
    first_obj = make_function_from_source("def first():\n    return 1\n", filename, "first")
    second_obj = make_function_from_source("def second():\n    return 2\n", filename, "second")
    assert callable(first_obj)
    assert callable(second_obj)
    first_payload = json.loads(create_function_payload(first_obj, target_name="first").decode())
    second_payload = json.loads(create_function_payload(second_obj, target_name="second").decode())
    assert is_object_mapping(first_payload)
    assert is_object_mapping(second_payload)
    module_payload = create_module_payload(
        module_code,
        {
            "first": first_payload["target"],
            "second": second_payload["target"],
        },
    )

    def mock_run_json_worker(
        worker_script: str, **kwargs: object
    ) -> tuple[dict[str, object], str, str]:
        assert "pysymex.module" in worker_script
        sandbox_cfg = kwargs.get("sandbox_config")
        assert is_object_mapping(sandbox_cfg)
        return ({"ok": True, "payload": json.loads(module_payload.decode("utf-8"))}, "", "")

    clear_module_extraction_cache()
    with patch("pysymex.sandbox.bridge.module._run_json_worker", side_effect=mock_run_json_worker):
        blob = extract_module(b"raise RuntimeError('host must not execute')", filename)

    assert isinstance(blob, ModuleBlob)
    assert blob.function_names() == ("first", "second")
    assert blob.reconstruct_module().co_filename == filename
    assert blob.get_function("first")() == 1
    assert blob.get_function("second")() == 2


@pytest.mark.timeout(30)
def test_extract_module_cache_prevents_repeated_sandbox_worker_for_same_file() -> None:
    """Repeated same-file extraction reuses the module payload instead of relaunching."""
    filename = "target.py"
    source = b"def target():\n    return 1\n"
    module_code = compile(source.decode("utf-8"), filename, "exec")
    func_obj = make_function_from_source(source.decode("utf-8"), filename, "target")
    assert callable(func_obj)
    function_payload = json.loads(create_function_payload(func_obj, target_name="target").decode())
    assert is_object_mapping(function_payload)
    module_payload = create_module_payload(module_code, {"target": function_payload["target"]})
    calls = 0

    def mock_run_json_worker(
        worker_script: str, **kwargs: object
    ) -> tuple[dict[str, object], str, str]:
        nonlocal calls
        _ = worker_script
        _ = kwargs
        calls += 1
        return ({"ok": True, "payload": json.loads(module_payload.decode("utf-8"))}, "", "")

    clear_module_extraction_cache()
    with patch("pysymex.sandbox.bridge.module._run_json_worker", side_effect=mock_run_json_worker):
        first_blob = extract_module(source, filename)
        second_blob = extract_module(source, filename)

    assert first_blob is second_blob
    assert calls == 1


def test_module_cache_key_uses_stable_source_digest() -> None:
    source = b"def target():\n    return 1\n"
    key = module_cache_key(source, "target.py", {"backend": "WINDOWS_APPCONTAINER"})

    assert key[0] == stable_digest_hex(source)
    assert key[1] == "target.py"
    assert len(key[0]) == 64


@pytest.mark.timeout(30)
def test_extract_module_runs_real_sandbox_worker_with_explicit_backend() -> None:
    """The single-pass module worker executes once and returns reusable targets."""
    clear_module_extraction_cache()
    blob = extract_module(
        b"VALUE = 4\n"
        b"def first(x: int, step: int = VALUE) -> int:\n"
        b"    return x + step\n"
        b"class Tools:\n"
        b"    @staticmethod\n"
        b"    def second(x: int) -> int:\n"
        b"        return x * 2\n",
        "target.py",
        sandbox_config=_real_worker_sandbox_config(),
        use_cache=False,
    )

    assert blob.function_names() == ("Tools.second", "first")
    assert blob.get_function("first")(3) == 7
    assert blob.get_function("Tools.second")(5) == 10


@pytest.mark.timeout(30)
def test_extract_module_reports_unserialized_requested_target() -> None:
    """Unsupported target metadata remains visible instead of looking absent."""
    clear_module_extraction_cache()
    blob = extract_module(
        b"UNSUPPORTED = object()\ndef target() -> object:\n    return UNSUPPORTED\n",
        "target.py",
        sandbox_config=_real_worker_sandbox_config(),
        use_cache=False,
    )

    with pytest.raises(
        ValueError,
        match=(
            "Function 'target' not found in sandbox module payload; diagnostics: "
            "WARNING: target 'target' was not serialized"
        ),
    ):
        blob.get_function("target")


@pytest.mark.timeout(30)
def test_extract_module_rejects_missing_payload_as_protocol_error() -> None:
    clear_module_extraction_cache()
    with patch(
        "pysymex.sandbox.bridge.module._run_json_worker", return_value=({"ok": True}, "", "")
    ):
        with pytest.raises(SandboxProtocolError, match="no module payload"):
            extract_module(
                b"def target():\n    return 1\n",
                "target.py",
                sandbox_config={},
            )


@pytest.mark.timeout(30)
def test_extract_module_reconstructs_real_sandbox_function_with_explicit_backend() -> None:
    """The extraction worker survives the sandbox harness pre-screening path."""
    blob = extract_module(
        b"VALUE = 4\ndef target(x: int, step: int = VALUE) -> int:\n    return x + step\n",
        "target.py",
        sandbox_config=_real_worker_sandbox_config(),
    ).get_function_blob("target")

    rebuilt = blob.reconstruct()

    assert rebuilt.__name__ == "target"
    assert rebuilt.__defaults__ == (4,)
    assert rebuilt.__annotations__ == {"x": "int", "step": "int", "return": "int"}
    assert rebuilt(3) == 7


@pytest.mark.timeout(30)
def test_extract_module_preserves_safe_contract_metadata() -> None:
    """String contracts cross the sandbox boundary as data, not live target objects."""
    blob = extract_module(
        b"from pysymex.contracts import ensures, requires\n"
        b"@requires('x > 0')\n"
        b"@ensures('__result__ > 0')\n"
        b"def target(x: int) -> int:\n"
        b"    return x\n",
        "target.py",
        sandbox_config=_real_worker_sandbox_config(),
    ).get_function_blob("target")

    rebuilt = blob.reconstruct()

    from pysymex.contracts.decorators import get_function_contract

    contract = get_function_contract(rebuilt)
    assert contract is not None
    assert [clause.condition for clause in contract.preconditions] == ["x > 0"]
    assert [clause.condition for clause in contract.postconditions] == ["__result__ > 0"]


@pytest.mark.timeout(30)
def test_function_blob_marks_callable_contracts_unknown_without_host_execution() -> None:
    """Callable contracts from untrusted modules must not run on the host."""
    filename = "target.py"
    func_obj = make_function_from_source("def target(x):\n    return x\n", filename, "target")
    assert callable(func_obj)
    payload = json.loads(create_function_payload(func_obj, target_name="target").decode("utf-8"))
    assert is_object_mapping(payload)
    target = payload["target"]
    assert is_object_mapping(target)
    target["contract"] = {
        "function_name": "target",
        "preconditions": [
            {
                "kind": "REQUIRES",
                "predicate_kind": "unsupported_callable",
                "predicate": None,
                "condition": "unsafe_predicate",
                "message": "Precondition: <callable>",
                "severity": "ERROR",
                "line_number": 1,
            }
        ],
        "postconditions": [],
    }
    blob = FunctionBlob(
        payload=json.dumps(payload).encode("utf-8"),
        filename=filename,
        function_name="target",
    )

    rebuilt = blob.reconstruct()

    from pysymex.contracts.decorators import get_function_contract

    contract = get_function_contract(rebuilt)
    assert contract is not None
    assert contract.preconditions[0].condition == "unsafe_predicate"
    with pytest.raises(TypeError, match="callable or string"):
        contract.preconditions[0].compile({})


@pytest.mark.timeout(30)
def test_function_blob_rejects_target_name_mismatch() -> None:
    filename = "target.py"
    func_obj = make_function_from_source("def target():\n    return 1\n", filename, "target")
    assert callable(func_obj)
    blob = FunctionBlob(
        payload=create_function_payload(func_obj, target_name="target"),
        filename=filename,
        function_name="other",
    )

    with pytest.raises(ValueError, match="target name mismatch"):
        blob.reconstruct()
