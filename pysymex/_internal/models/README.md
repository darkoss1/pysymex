# Model package ownership

`pysymex._internal.models` contains adapters for Python runtime behavior. Its external
interface is `pysymex._internal.models.registry`; callers should not compose family
registries themselves.

The package has four intentional implementation families:

- `contracts`: interfaces, result records, and invocation capabilities. It
  cannot depend on concrete model families.
- `shared`: behavior reused by builtin and stdlib adapters. It can depend on
  `contracts`, but not on concrete model families.
- `builtins`: adapters owned by Python builtins. Global builtin functions live
  directly in semantic subpackages; builtin type methods live under `types`.
- `stdlib`: adapters grouped by their public standard-library module.

The `operator` stdlib family delegates `iadd`, `iconcat`, and `imul` through the
invocation capability to the canonical builtin dunder adapters. Concrete
families therefore remain independent while sharing one implementation of the
mutation semantics.

Semantic carriers are not model adapters. Python class, instance, method, and
descriptor carriers therefore live in `pysymex._internal.core.classes`, not here. Their
runtime export surface is `pysymex._internal.core.classes.api`; the package initializer
remains import-free like other core subpackages.

Registry ownership follows the same rule: builtin adapters are registered only
by the builtin registry, stdlib adapters only by the stdlib registry, and the
runtime registry composes both without duplicating qualnames.
Canonical qualnames always resolve. Short stdlib names resolve only when one
model owns the name; ambiguous names require a canonical or explicit alias.
