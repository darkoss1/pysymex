# Models

Runtime models give the VM precise behavior for supported builtins, containers, standard-library
functions, numeric operations, objects, and concurrency primitives. They extend CPython-compatible
execution; they do not replace it wholesale.

## Method

1. The call dispatcher resolves a call target.
2. Builtin and stdlib registries look for a matching model.
3. A model returns a value, constraints, and side effects.
4. The dispatcher records modeled writes, branches on modeled exceptions, and appends constraints.
5. Detector-facing side effects become issues only when feasibility evidence supports them.

Models can return exact concrete values, symbolic values with type constraints, potential exception
effects, definite exception effects, mutation effects, and precision-loss markers.

## Model Families

| Family | Examples |
| --- | --- |
| Builtins | `int`, `float`, `bool`, `str`, `len`, `range`, `sum`, `min`, `max`, exceptions |
| Containers | `list`, `dict`, `set`, `tuple`, `bytes`, `bytearray`, `str` methods |
| Standard library | `math`, `itertools`, `functools`, `collections`, `dataclasses`, `pathlib`, `re`, `os.path` |
| Objects | classes, instances, descriptors, attributes |
| Concurrency | selected `threading` and `asyncio` abstractions |

## Evidence And Exceptions

Potential model exceptions fork success and exception paths when the active exception handler can
catch them. Definite model exceptions enter matching handlers when possible. Uncaught modeled
exceptions are published as issues only after feasibility checks.

When a model cannot preserve precise behavior, it should return explicit degradation or unsupported
evidence. Silent concrete approximation is unsafe because it can hide bugs or create false reports.

## Evidence In Source

- Call model dispatch: `pysymex/execution/calls/model_dispatch.py`
- Builtin registry: `pysymex/models/builtins`
- Container models: `pysymex/models/containers`
- Standard-library models: `pysymex/models/stdlib`
- Object and numeric models: `pysymex/models/objects`, `pysymex/models/numeric`
- Tests: `tests/unit/models`, `tests/unit/scanner/test_core_*`

## Limits

Model coverage is intentionally incomplete. Unsupported dunder behavior, dynamic reflection,
native extensions, broad I/O, and unmodeled side effects must remain explicit. A modeled result is
evidence for that modeled behavior, not proof that all CPython behavior was represented.
