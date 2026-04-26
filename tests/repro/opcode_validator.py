import dis
import z3
import logging
from typing import Any, Dict, Optional, List, Tuple
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig, ExecutionResult
from pysymex.core.types.scalars import SymbolicValue

# Configure logging to be quiet during validation
logging.getLogger("pysymex").setLevel(logging.ERROR)


def run_cpython(code_str: str, initial_locals: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Executes code via exec() to get ground truth from CPython.
    """
    locs = initial_locals.copy() if initial_locals else {}
    globs = {}
    try:
        exec(code_str, globs, locs)
        return {"locals": locs, "globals": globs, "exception": None, "stack": []}
    except Exception as e:
        return {"locals": locs, "globals": globs, "exception": type(e).__name__, "stack": []}


def run_pysymex(
    code_str: str,
    symbolic_vars: Optional[Dict[str, str]] = None,
    initial_values: Optional[Dict[str, Any]] = None,
) -> ExecutionResult:
    """
    Uses SymbolicExecutor to get symbolic results.
    """
    config = ExecutionConfig(
        max_paths=1, max_depth=100, enable_chtd=False, enable_abstract_interpretation=False
    )
    executor = SymbolicExecutor(config)

    arg_names = list(symbolic_vars.keys()) if symbolic_vars else []
    wrapper_code = f"def wrapper({', '.join(arg_names)}):\n"

    if initial_values:
        for var, val in initial_values.items():
            if not symbolic_vars or var not in symbolic_vars:
                if isinstance(val, str):
                    wrapper_code += f"    {var} = {repr(val)}\n"
                else:
                    wrapper_code += f"    {var} = {val}\n"

    for line in code_str.splitlines():
        wrapper_code += f"    {line}\n"

    wrapper_code += "    return\n"

    globs = {}
    exec(wrapper_code, globs)
    wrapper_func = globs["wrapper"]

    return executor.execute_function(
        wrapper_func, symbolic_args=symbolic_vars, initial_values=initial_values
    )


def compare_values(sym_val: Any, concrete_val: Any, constraints: List[z3.BoolRef]) -> bool:
    """
    Z3-based robust comparator.
    Checks if sym_val == concrete_val holds under constraints.
    """
    if not isinstance(sym_val, SymbolicValue):
        return sym_val == concrete_val

    solver = z3.Solver()
    for c in constraints:
        solver.add(c)

    if isinstance(concrete_val, bool):
        if concrete_val:
            cond = sym_val.could_be_truthy()
        else:
            cond = sym_val.could_be_falsy()
    elif isinstance(concrete_val, int):
        cond = sym_val.z3_int == concrete_val
    elif concrete_val is None:
        cond = sym_val.is_none
    else:
        return False

    solver.add(z3.Not(cond))
    result = solver.check()
    return result == z3.unsat


def validate_opcode(
    code_str: str,
    symbolic_vars: Optional[Dict[str, str]] = None,
    initial_values: Optional[Dict[str, Any]] = None,
    expected_locals: Optional[Dict[str, Any]] = None,
    description: str = "",
) -> Tuple[bool, str]:
    """
    Main entry point for validation.
    Returns (Success, Message).
    """
    cp = run_cpython(code_str, initial_locals=initial_values)
    ps = run_pysymex(code_str, symbolic_vars=symbolic_vars, initial_values=initial_values)

    print(
        f"DEBUG {description}: PS Locals: {list(ps.final_locals.keys())}, PS Globals: {list(ps.final_globals.keys())}"
    )

    constraints = ps.issues[0].constraints if ps.issues else []

    if cp["exception"]:
        if ps.final_exception is None and not ps.issues:
            return (
                False,
                f"Bugs found: CPython raised {cp['exception']}, but pysymex did not. {description}",
            )
        return True, "Passed (Exception match)"

    if expected_locals:
        for var, val in expected_locals.items():
            res_val = ps.final_locals.get(var)
            if res_val is None:
                res_val = ps.final_globals.get(var)

            if res_val is None:
                return (
                    False,
                    f"Bugs found: Variable '{var}' missing in pysymex results. {description}",
                )

            if not compare_values(res_val, val, constraints):
                return (
                    False,
                    f"Bugs found: Value mismatch for '{var}'. Expected {val}, got {res_val}. {description}",
                )

    if len(ps.final_stack) > 0:
        pass

    return True, "Passed"


if __name__ == "__main__":
    success, msg = validate_opcode("x = 1 + 2", expected_locals={"x": 3})
    print(f"Self-check: {msg}")
