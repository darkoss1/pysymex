"""
Function Summary logic classes for pysymex.
Phase 20: Builders, registry, composition, analysis.
"""

from __future__ import annotations


from typing import (
    Any,
    cast,
)


import z3


from pysymex.core.solver import create_solver

from pysymex.analysis.summaries.types import (
    CallSite,
    ExceptionInfo,
    FunctionSummary,
    ModifiedVariable,
    ParameterInfo,
    ReadVariable,
)


class SummaryBuilder:
    """
    Builds function summaries from analysis results.
    """

    def __init__(self, name: str):
        self.summary = FunctionSummary(name=name)

        self._param_index = 0

    def set_qualname(self, qualname: str) -> SummaryBuilder:
        """Set qualified name."""

        self.summary.qualname = qualname

        return self

    def set_module(self, module: str) -> SummaryBuilder:
        """Set module name."""

        self.summary.module = module

        return self

    def add_parameter(
        self,
        name: str,
        type_hint: str | None = None,
        default: Any = None,
    ) -> SummaryBuilder:
        """Add a parameter."""

        param = ParameterInfo(
            name=name,
            index=self._param_index,
            type_hint=type_hint,
            default_value=default,
        )

        self.summary.parameters.append(param)

        self._param_index += 1

        return self

    def set_return_type(self, type_hint: str) -> SummaryBuilder:
        """Set return type."""

        self.summary.return_type = type_hint

        return self

    def require(self, condition: z3.BoolRef) -> SummaryBuilder:
        """Add a precondition."""

        self.summary.add_precondition(condition)

        return self

    def ensure(self, condition: z3.BoolRef) -> SummaryBuilder:
        """Add a postcondition."""

        self.summary.add_postcondition(condition)

        return self

    def modifies(
        self,
        name: str,
        scope: str = "local",
        object_path: str | None = None,
    ) -> SummaryBuilder:
        """Add a modified variable."""

        self.summary.add_modified(ModifiedVariable(name, scope, object_path))

        return self

    def reads_var(
        self,
        name: str,
        scope: str = "local",
        object_path: str | None = None,
    ) -> SummaryBuilder:
        """Add a read variable."""

        self.summary.add_reads(ReadVariable(name, scope, object_path))

        return self

    def calls_function(
        self,
        callee: str,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        pc: int = 0,
    ) -> SummaryBuilder:
        """Add a function call."""

        self.summary.add_call(
            CallSite(
                callee=callee,
                args=args or [],
                kwargs=kwargs or {},
                pc=pc,
            )
        )

        return self

    def may_raise_exception(
        self,
        exc_type: str,
        condition: z3.BoolRef | None = None,
    ) -> SummaryBuilder:
        """Add a potential exception."""

        self.summary.add_exception(ExceptionInfo(exc_type, condition))

        return self

    def mark_pure(self) -> SummaryBuilder:
        """Mark as pure function."""

        self.summary.is_pure = True

        return self

    def mark_recursive(self) -> SummaryBuilder:
        """Mark as recursive."""

        self.summary.is_recursive = True

        return self

    def set_complexity(self, complexity: str) -> SummaryBuilder:
        """Set complexity class."""

        self.summary.complexity = complexity

        return self

    def set_return_constraint(self, constraint: z3.BoolRef) -> SummaryBuilder:
        """Set return value constraint."""

        self.summary.return_constraint = constraint

        return self

    def build(self) -> FunctionSummary:
        """Build the summary."""

        return self.summary


class SummaryRegistry:
    """
    Registry of function summaries.
    Stores and retrieves summaries by function name/qualname.
    """

    def __init__(self):
        self._summaries: dict[str, FunctionSummary] = {}

        self._by_module: dict[str, list[str]] = {}

    def register(self, summary: FunctionSummary) -> None:
        """Register a function summary."""

        key = summary.qualname or summary.name

        self._summaries[key] = summary

        if summary.module:
            if summary.module not in self._by_module:
                self._by_module[summary.module] = []

            self._by_module[summary.module].append(key)

    def get(self, name: str) -> FunctionSummary | None:
        """Get summary by name."""

        return self._summaries.get(name)

    def get_for_module(self, module: str) -> list[FunctionSummary]:
        """Get all summaries for a module."""

        names = self._by_module.get(module, [])

        return [self._summaries[n] for n in names if n in self._summaries]

    def has(self, name: str) -> bool:
        """Check if summary exists."""

        return name in self._summaries

    def all_summaries(self) -> list[FunctionSummary]:
        """Get all registered summaries."""

        return list(self._summaries.values())

    def clear(self) -> None:
        """Clear all summaries."""

        self._summaries.clear()

        self._by_module.clear()


SUMMARY_REGISTRY = SummaryRegistry()


def get_summary(name: str) -> FunctionSummary | None:
    """Get summary from global registry."""

    return SUMMARY_REGISTRY.get(name)


def register_summary(summary: FunctionSummary) -> None:
    """Register summary in global registry."""

    SUMMARY_REGISTRY.register(summary)


def compose_summaries(
    outer: FunctionSummary,
    call_site: CallSite,
    inner: FunctionSummary,
) -> FunctionSummary:
    """
    Compose an outer summary with an inner call.
    Creates a new summary for outer that incorporates the effects
    of calling inner.
    """

    result = outer.clone()

    for mod in inner.modified:
        if mod.scope in ("global", "nonlocal"):
            result.add_modified(mod)

    for exc in inner.may_raise:
        result.add_exception(exc)

    if not inner.is_pure:
        result.is_pure = False

    if not inner.is_deterministic:
        result.is_deterministic = False

    return result


def instantiate_summary(
    summary: FunctionSummary,
    args: list[z3.ExprRef],
    kwargs: dict[str, z3.ExprRef],
) -> tuple[z3.BoolRef, z3.BoolRef, z3.ExprRef | None]:
    """
    Instantiate a summary with concrete/symbolic arguments.
    Returns (precondition, postcondition, return_value).
    """

    subst = {}

    for i, param in enumerate(summary.parameters):
        if i < len(args):
            old_var = param.to_z3()

            subst[old_var] = args[i]

        elif param.name in kwargs:
            old_var = param.to_z3()

            subst[old_var] = kwargs[param.name]

    pre_conds: list[z3.ExprRef | z3.BoolRef] = []

    for cond in summary.preconditions:
        instantiated = z3.substitute(cond, *subst.items()) if subst else cond

        pre_conds.append(instantiated)

    precondition = z3.And(*pre_conds) if pre_conds else z3.BoolVal(True)

    post_conds: list[z3.ExprRef | z3.BoolRef] = []

    for cond in summary.postconditions:
        instantiated = z3.substitute(cond, *subst.items()) if subst else cond

        post_conds.append(instantiated)

    postcondition = z3.And(*post_conds) if post_conds else z3.BoolVal(True)

    return_val = summary.return_var

    if summary.return_constraint:
        pass

    return precondition, postcondition, return_val


def create_builtin_summaries() -> list[FunctionSummary]:
    """Create summaries for built-in functions."""

    summaries: list[FunctionSummary] = []

    len_summary = (
        SummaryBuilder("len")
        .set_qualname("builtins.len")
        .add_parameter("obj", "object")
        .set_return_type("int")
        .mark_pure()
        .build()
    )

    len_summary.return_constraint = cast(z3.ArithRef, len_summary.return_var) >= 0

    summaries.append(len_summary)

    abs_summary = (
        SummaryBuilder("abs")
        .set_qualname("builtins.abs")
        .add_parameter("x", "int")
        .set_return_type("int")
        .mark_pure()
        .build()
    )

    x = abs_summary.parameters[0].to_z3()

    result = cast(z3.ArithRef, abs_summary.return_var)

    abs_summary.postconditions.append(result >= 0)

    abs_summary.postconditions.append(z3.Or(result == x, result == -x))

    summaries.append(abs_summary)

    min_summary = (
        SummaryBuilder("min")
        .set_qualname("builtins.min")
        .add_parameter("args", "iterable")
        .set_return_type("int")
        .mark_pure()
        .build()
    )

    summaries.append(min_summary)

    max_summary = (
        SummaryBuilder("max")
        .set_qualname("builtins.max")
        .add_parameter("args", "iterable")
        .set_return_type("int")
        .mark_pure()
        .build()
    )

    summaries.append(max_summary)

    sum_summary = (
        SummaryBuilder("sum")
        .set_qualname("builtins.sum")
        .add_parameter("iterable", "iterable")
        .add_parameter("start", "int", default=0)
        .set_return_type("int")
        .mark_pure()
        .build()
    )

    summaries.append(sum_summary)

    print_summary = (
        SummaryBuilder("print")
        .set_qualname("builtins.print")
        .add_parameter("args", "object")
        .set_return_type("None")
        .modifies("stdout", scope="global")
        .build()
    )

    print_summary.is_pure = False

    summaries.append(print_summary)

    input_summary = (
        SummaryBuilder("input")
        .set_qualname("builtins.input")
        .add_parameter("prompt", "str", default="")
        .set_return_type("str")
        .reads_var("stdin", scope="global")
        .build()
    )

    input_summary.is_pure = False

    input_summary.is_deterministic = False

    summaries.append(input_summary)

    return summaries


def register_builtin_summaries() -> None:
    """Register built-in function summaries."""

    for summary in create_builtin_summaries():
        register_summary(summary)


class SummaryAnalyzer:
    """
    Analyzes function summaries for various properties.
    """

    def __init__(self, registry: SummaryRegistry | None = None):
        self.registry = registry or SUMMARY_REGISTRY

    def is_pure(self, name: str) -> bool:
        """Check if function is pure."""

        summary = self.registry.get(name)

        if summary:
            return summary.is_pure

        return False

    def may_modify_globals(self, name: str) -> bool:
        """Check if function may modify global state."""

        summary = self.registry.get(name)

        if summary:
            return summary.modifies_globals()

        return True

    def get_called_functions(self, name: str) -> set[str]:
        """Get all functions called by this function."""

        summary = self.registry.get(name)

        if summary:
            return {call.callee for call in summary.calls}

        return set()

    def get_transitive_calls(self, name: str, visited: set[str] | None = None) -> set[str]:
        """Get all functions transitively called."""

        if visited is None:
            visited = set[str]()

        if name in visited:
            return set()

        visited.add(name)

        result: set[str] = set()

        direct_calls = self.get_called_functions(name)

        result.update(direct_calls)

        for callee in direct_calls:
            result.update(self.get_transitive_calls(callee, visited))

        return result

    def check_preconditions(
        self,
        name: str,
        args: list[z3.ExprRef],
        path_constraints: list[z3.BoolRef],
    ) -> tuple[bool, dict[str, Any] | None]:
        """
        Check if preconditions are satisfied.
        Returns (satisfied, counterexample or None).
        """

        summary = self.registry.get(name)

        if not summary or not summary.preconditions:
            return True, None

        pre, _, _ = instantiate_summary(summary, args, {})

        solver = create_solver()

        for pc in path_constraints:
            solver.add(pc)

        solver.add(z3.Not(pre))

        if solver.check() == z3.sat:
            model = solver.model()

            counterexample = {str(d.name()): model[d] for d in model.decls()}

            return False, counterexample

        return True, None
