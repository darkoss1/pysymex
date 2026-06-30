"""Tests for the shared symbolic module-model boundary."""

from __future__ import annotations

from typing import cast

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.modules import (
    GenericModuleModel,
    ModuleModelRegistry,
    materialize_module,
)
from pysymex._internal.models.stdlib.sys.module import SysModuleModel


def test_registry_materializes_registered_sys_namespace() -> None:
    state = VMState()

    materialized = materialize_module("sys", state, registered_only=True)

    assert materialized is not None
    module, next_state = materialized
    namespace = next_state.load_heap(module.address)
    assert isinstance(namespace, dict)
    assert namespace["__module_name__"] == "sys"
    assert isinstance(namespace["argv"], SymbolicList)
    assert isinstance(namespace["path"], SymbolicList)
    assert isinstance(namespace["modules"], SymbolicDict)
    assert namespace["platform"] == __import__("sys").platform
    assert namespace["version_info"] == tuple(__import__("sys").version_info)


def test_static_and_dynamic_imports_share_os_materialization() -> None:
    state = VMState()

    materialized = materialize_module("os", state, registered_only=True)

    assert materialized is not None
    module, next_state = materialized
    namespace = next_state.load_heap(module.address)
    assert isinstance(namespace, dict)
    assert isinstance(namespace["environ"], SymbolicDict)
    path = cast("object", namespace["path"])
    assert isinstance(path, SymbolicObject)
    path_namespace = next_state.load_heap(path.address)
    assert path_namespace == {"__module_name__": "os.path"}


def test_unknown_module_gets_generic_namespace_only_when_allowed() -> None:
    state = VMState()
    assert materialize_module("application_module", state, registered_only=True) is None

    materialized = materialize_module("application_module", state)
    assert materialized is not None
    module, next_state = materialized
    assert next_state.load_heap(module.address) == {"__module_name__": "application_module"}


def test_module_registry_rejects_duplicate_ownership() -> None:
    registry = ModuleModelRegistry()
    registry.register(SysModuleModel())

    with pytest.raises(ValueError, match="duplicate"):
        registry.register(SysModuleModel())


def test_generic_model_uses_stable_module_identity() -> None:
    first, _ = GenericModuleModel("example").materialize(VMState())
    second, _ = GenericModuleModel("example").materialize(VMState())

    assert first.address == second.address
