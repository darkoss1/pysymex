"""Architecture invariants for model ownership and registry composition."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.models.builtins.registry.models import get_default_model_registry
from pysymex._internal.models.registry import RuntimeModelRegistry
from pysymex._internal.models.stdlib.registry import extended_stdlib_registry

_BUILTIN_OWNERS = {
    "builtins",
    "bytearray",
    "bytes",
    "complex",
    "dict",
    "float",
    "frozenset",
    "int",
    "list",
    "memoryview",
    "set",
    "str",
    "tuple",
}


def _owner(model: object) -> str:
    qualname = getattr(model, "qualname", "")
    assert isinstance(qualname, str) and qualname
    return qualname.split(".", 1)[0]


def test_models_top_level_contains_only_intentional_families() -> None:
    models_root = Path(__file__).parents[3] / "pysymex" / "_internal" / "models"
    packages = {
        path.name for path in models_root.iterdir() if path.is_dir() and path.name != "__pycache__"
    }
    assert packages == {"builtins", "contracts", "stdlib"}


def test_family_registries_have_disjoint_ownership_and_qualnames() -> None:
    builtin_models = get_default_model_registry().models()
    stdlib_models = extended_stdlib_registry.models()

    assert {_owner(model) for model in builtin_models} <= _BUILTIN_OWNERS
    assert not ({_owner(model) for model in stdlib_models} & _BUILTIN_OWNERS)

    builtin_qualnames = {model.qualname for model in builtin_models}
    stdlib_qualnames = {model.qualname for model in stdlib_models}
    assert builtin_qualnames.isdisjoint(stdlib_qualnames)


def test_runtime_registry_is_the_single_composed_interface() -> None:
    registry = RuntimeModelRegistry.default()

    assert registry.get("builtins.len") is not None
    assert registry.get("str.split") is not None
    assert registry.get("threading.Lock") is not None
    assert registry.get("math.sqrt") is not None
    assert len(registry.models()) == len({model.qualname for model in registry.models()})


def test_stdlib_short_names_only_resolve_when_unambiguous() -> None:
    registry = RuntimeModelRegistry.default()

    assert registry.get("chain") is registry.get("itertools.chain")
    assert registry.get("compress") is None
