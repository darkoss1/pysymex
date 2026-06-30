"""Architecture checks for domain-owned model result factories."""

from __future__ import annotations

from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.registry import RuntimeModelRegistry


def test_model_result_exposes_typed_factories() -> None:
    for name in ("none", "int", "bool", "symbolic_int", "symbolic_bool", "method_type_error"):
        method = getattr(ModelResult, name)
        assert callable(method)
        assert getattr(method, "__self__", None) is ModelResult


def test_side_effects_empty_is_callable_factory() -> None:
    effects = SideEffects.empty()
    assert effects == {}
    assert SideEffects.empty() is not effects


def test_side_effects_type_error_builds_raised_exception_payload() -> None:
    effects = SideEffects.type_error("unit.source", "bad args")
    assert SideEffects.is_raised_exception(effects["raised_exception"])
    assert effects["raised_exception"]["exception_type"] == "TypeError"


def test_runtime_registry_default_is_singleton() -> None:
    assert RuntimeModelRegistry.default() is RuntimeModelRegistry.default()


def test_builtin_helper_facades_do_not_reexport_side_effect_aliases() -> None:
    import pysymex._internal.models.builtins.common.builtin_policies as builtin_policies
    import pysymex._internal.models.builtins.common.dynamic as dynamic

    for module in (builtin_policies, dynamic):
        for alias in (
            "type_error_side_effect",
            "value_error_side_effect",
            "zero_division_error_side_effect",
            "resolve_heap_object",
            "literal_string_value",
        ):
            assert not hasattr(module, alias)


def test_symbolic_carriers_expose_domain_owned_resolvers() -> None:
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.core.types.scalars.strings import SymbolicString

    for owner, name in (
        (SymbolicObject, "resolve"),
        (SymbolicList, "resolve"),
        (SymbolicString, "resolve"),
        (SymbolicString, "concrete_literal"),
    ):
        assert callable(getattr(owner, name))
        assert name in owner.__dict__


from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_model_result_int_factory_uses_symbolic_int_constraints() -> None:
    value, constraints = ModelResult.symbolic_int("unit")
    result = ModelResult.int("unit")
    assert isinstance(result.value, SymbolicValue)
    assert isinstance(value, SymbolicValue)
    assert result.value.name == value.name
    assert list(result.constraints) == constraints
