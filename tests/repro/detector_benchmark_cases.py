"""Curated runtime detector benchmark case inventory."""

from __future__ import annotations

from tests.repro.detector_benchmark_types import BenchmarkCase


RUNTIME_CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase("assertion-error", "assertion_error_positive", {"x": "int"}, True),
    BenchmarkCase("assertion-error", "assertion_error_negative", {}, False),
    BenchmarkCase("attribute-error", "attribute_error_positive", {}, True),
    BenchmarkCase("attribute-error", "attribute_error_negative", {}, False),
    BenchmarkCase("division-by-zero", "division_by_zero_positive", {"x": "int"}, True),
    BenchmarkCase("division-by-zero", "division_by_zero_negative", {}, False),
    BenchmarkCase(
        "division-by-zero",
        "division_by_zero_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int", "x": "int"},
        True,
    ),
    BenchmarkCase(
        "division-by-zero",
        "division_by_zero_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
    BenchmarkCase("index-error", "index_error_positive", {"i": "int"}, True),
    BenchmarkCase("index-error", "index_error_negative", {}, False),
    BenchmarkCase("index-error", "index_error_pop_empty_positive", {}, True),
    BenchmarkCase("index-error", "index_error_pop_nonempty_negative", {}, False),
    BenchmarkCase("key-error", "key_error_positive", {"k": "str"}, True),
    BenchmarkCase("key-error", "key_error_negative", {}, False),
    BenchmarkCase("none-dereference", "none_dereference_positive", {}, True),
    BenchmarkCase("none-dereference", "none_dereference_negative", {}, False),
    BenchmarkCase("overflow", "overflow_positive", {"x": "int", "y": "int"}, True),
    BenchmarkCase("overflow", "overflow_negative", {}, False),
    BenchmarkCase("resource-leak", "resource_leak_positive", {}, True),
    BenchmarkCase("resource-leak", "resource_leak_negative", {}, False),
    BenchmarkCase(
        "resource-leak",
        "resource_leak_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        True,
    ),
    BenchmarkCase(
        "resource-leak",
        "resource_leak_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
    BenchmarkCase("type-error", "type_error_positive", {"x": "int"}, True),
    BenchmarkCase("type-error", "type_error_negative", {}, False),
    BenchmarkCase("unbound-variable", "unbound_variable_positive", {"x": "int"}, True),
    BenchmarkCase("unbound-variable", "unbound_variable_negative", {"x": "int"}, False),
    BenchmarkCase("value-error", "value_error_positive", {}, True),
    BenchmarkCase("value-error", "value_error_negative", {}, False),
    BenchmarkCase("value-error", "value_error_range_zero_step_positive", {"step": "int"}, True),
    BenchmarkCase("value-error", "value_error_range_nonzero_step_negative", {}, False),
    BenchmarkCase(
        "value-error",
        "value_error_path_explosion_positive",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        True,
    ),
    BenchmarkCase(
        "value-error",
        "value_error_path_explosion_negative",
        {"a": "int", "b": "int", "c": "int", "d": "int", "e": "int", "f": "int"},
        False,
    ),
)
