## PySyMex Contract System — Full Engineering Design

---

## 1. Foundational Philosophy

A contract in PySyMex is not a documentation annotation or a runtime assertion. It is a **first-class symbolic constraint** injected directly into the path constraint set at bytecode-level execution points. Every contract clause becomes a Z3 formula that participates in CHTD decomposition, Thompson Sampling reward computation, and logical contradiction detection identically to any other path constraint.

The contract system has three guarantees that distinguish it from every existing Python contract library:

1. **Soundness** — a contract violation means a mathematically reachable path exists where the constraint is violated, with a concrete witness
2. **Completeness** — no contract violation is missed if the path is reachable within the exploration budget
3. **Zero impedance** — contracts live at bytecode level, so there is no translation gap between what the contract says and what the executor reasons about

---

## 2. Contract Taxonomy

### 2.1 Preconditions — `@requires`

Constraints that must hold at function entry. Injected at the first bytecode instruction of the function frame, before any local bindings are established.

```python
from pysymex.contracts import requires, ensures, invariant, assumes, assigns

@requires(lambda x, y: x > 0, "x must be positive")
@requires(lambda x, y: y != 0, "y must be nonzero")
def divide(x: int, y: int) -> float:
    return x / y
```

At bytecode level, `RESUME` (Python 3.11+) or the first `LOAD_FAST` is the injection point. The precondition formula is added to the path constraint set immediately, before any instruction executes. This means:

- If the precondition is UNSAT given the caller's path constraints, PySyMex reports a **precondition impossibility** — the function can never be called with valid inputs on this path
- If the precondition is SAT, its constraint strengthens the path state, narrowing the symbolic input space for all subsequent instructions

### 2.2 Postconditions — `@ensures`

Constraints that must hold at function exit. The return value is bound to a special symbolic variable `result` that participates in the constraint.

```python
@ensures(lambda result, x, y: result == x / y, "result matches division")
@ensures(lambda result, x, y: result > 0, "result is positive given positive inputs")
def divide(x: int, y: int) -> float:
    return x / y
```

Injection point: every `RETURN_VALUE` and `RETURN_CONST` bytecode instruction. At each return site, the postcondition is checked against the current path constraint set. This is critical — a function with multiple return paths has its postcondition checked independently at each return site, not once at a merged exit point.

### 2.3 Frame Invariants — `@invariant`

Constraints that must hold at every bytecode instruction boundary within the function. These are the most powerful and most expensive contract type.

```python
@invariant(lambda self: self.size >= 0, "size never negative")
@invariant(lambda self: len(self.data) == self.size, "data length matches size")
class BoundedStack:
    def push(self, item: object) -> None:
        self.data.append(item)
        self.size += 1
```

Injection point: every instruction boundary — `STORE_FAST`, `STORE_ATTR`, `STORE_SUBSCR`, `CALL`, `RETURN_VALUE`. At each mutation point, the invariant is re-evaluated against the updated symbolic state. Violations are reported with the exact bytecode offset where the invariant first breaks.

### 2.4 Assumption Contracts — `@assumes`

Constraints that are asserted true without proof — they narrow the symbolic input space without generating a verification obligation. Used to encode external guarantees (OS behavior, hardware properties, library postconditions).

```python
@assumes(lambda n: n >= 0, "os.getpid() always nonneg")
def get_pid() -> int:
    return os.getpid()
```

These inject constraints into the path constraint set as hard facts, directly strengthening CHTD's decomposition by reducing the symbolic input space. They also enable Tier 4 cross-module contradiction detection — if a caller's path constraints contradict an `@assumes` clause, PySyMex reports a **cross-boundary contradiction**.

### 2.5 Frame Assignments — `@assigns`

Declares exactly which memory locations a function modifies. Anything not listed is guaranteed unmodified. This integrates directly with the AliasingAnalyzer.

```python
@assigns("self.size", "self.data")
def push(self, item: object) -> None:
    self.data.append(item)
    self.size += 1
```

At bytecode level, every `STORE_ATTR`, `STORE_SUBSCR`, `STORE_FAST` is checked against the assigns set. A write to an unlisted location is a contract violation. This eliminates the O(N²) aliasing queries for functions with `@assigns` — the AliasingAnalyzer can short-circuit to "no alias" for any location not in the assigns set without an SMT query.

### 2.6 Temporal Contracts — `@sequence`

Constraints on the *order* of operations — state machine contracts.

```python
@sequence(
    states=["closed", "open", "reading"],
    transitions={
        "closed": ["open"],
        "open": ["reading", "closed"],
        "reading": ["closed"],
    },
    initial="closed"
)
class FileHandle:
    def open(self) -> None: ...
    def read(self) -> bytes: ...
    def close(self) -> None: ...
```

At bytecode level, every method call that transitions state is tracked symbolically. The state variable is a symbolic Z3 enumeration sort. Illegal transitions produce UNSAT constraints that PySyMex reports as **state machine violations** — Tier 5 contradiction detection.

---

## 3. Type-Level Contract Integration

### 3.1 Refined Types

The type annotation system is extended to carry symbolic constraints inline with types:

```python
from pysymex.contracts import Refined, Positive, NonZero, Bounded

# Refined types — type + constraint in one
Positive = Refined[int, lambda x: x > 0]
NonZero = Refined[int, lambda x: x != 0]
Bounded = Refined[int, lambda x, lo, hi: lo <= x <= hi]
Percentage = Refined[float, lambda x: 0.0 <= x <= 1.0]
NonEmpty = Refined[list, lambda x: len(x) > 0]

def divide(x: Positive, y: NonZero) -> Positive:
    return x / y
```

At bytecode level, refined type annotations at `LOAD_FAST` injection points automatically generate preconditions. The type annotation becomes a constraint in the path constraint set without the developer writing a separate `@requires`. This enables Pyright/mypy to check type-level contracts statically while PySyMex checks them symbolically.

### 3.2 Dependent Types

Constraints between parameters:

```python
from pysymex.contracts import Depends

def slice_array(
    arr: list[int],
    start: Depends[int, lambda start, arr: 0 <= start < len(arr)],
    end: Depends[int, lambda end, start, arr: start <= end <= len(arr)]
) -> list[int]:
    return arr[start:end]
```

`Depends` creates a cross-parameter constraint in Z3. This is directly expressible as a QF_LIA formula and integrates with constraint independence clustering — `start` and `end` and `arr` are in the same Union-Find cluster by construction.

### 3.3 Effect Types

Annotations that declare side effects symbolically:

```python
from pysymex.contracts import Pure, Reads, Writes

@Pure  # no side effects — same inputs always same outputs
def compute_hash(data: bytes) -> int: ...

@Reads("self.config")  # reads but doesn't write
def get_setting(self, key: str) -> str: ...

@Writes("self.cache")  # writes only to cache
def update_cache(self, key: str, value: object) -> None: ...
```

`@Pure` enables aggressive memoization in the symbolic executor — the same symbolic inputs always produce the same symbolic output, so the function is evaluated once and the result is cached in the path constraint set. This directly eliminates redundant solver calls for pure functions called multiple times with the same symbolic arguments.

---

## 4. Bytecode Injection Architecture

### 4.1 Injection Point Classification

Every CPython bytecode instruction falls into one of five categories for contract injection:

```python
from enum import Enum

class InjectionPoint(Enum):
    FRAME_ENTRY    = "RESUME"                          # function entry
    FRAME_EXIT     = "RETURN_VALUE | RETURN_CONST"    # function exit  
    STORE_LOCAL    = "STORE_FAST | STORE_DEREF"       # local mutation
    STORE_ATTR     = "STORE_ATTR | STORE_SUBSCR"      # object mutation
    CALL_SITE      = "CALL | CALL_FUNCTION_EX"        # function call
    BRANCH         = "POP_JUMP_IF_* | JUMP_IF_*"      # branch point
    EXCEPTION      = "PUSH_EXC_INFO | RERAISE"        # exception path
```

Each contract type attaches to a subset of injection points. The injection is not monkey-patching or bytecode rewriting — it's hooks in the symbolic executor's instruction dispatch loop, fired at the corresponding opcode.

### 4.2 Contract Compilation

At analysis time, contract lambda expressions are compiled to Z3 formulas once and cached. The compilation pipeline:

```
Contract lambda
    ↓
Python AST (ast.parse on lambda source)
    ↓  
Symbolic expression builder
    ↓
Z3 formula over symbolic parameter variables
    ↓
Cached by (function_id, contract_index)
```

The Z3 formula is constructed once per contract per function, not once per invocation. At invocation time, the cached formula is instantiated with the current symbolic values of the parameters — a cheap substitution operation rather than a full compilation.

### 4.3 Contract Constraint Integration

When a contract is evaluated at an injection point:

```
Current path constraints C
    +
Contract formula F(symbolic_params)
    ↓
slice_for_query(C + F, F)  →  relevant constraints R
    ↓
solver.check(R)
    ↓
SAT   → contract holds, add F to path constraints
UNSAT → contract violation, extract witness, report bug
```

The contract formula becomes a permanent addition to the path constraint set when it holds. This is the crucial integration — a postcondition that proves `result > 0` narrows the symbolic state for all subsequent code that uses the return value. Downstream constraints benefit from this narrowing without any additional solver cost.

### 4.4 CHTD Integration

Contract constraints register in the CIG identically to branch constraints. A `@requires(lambda x, y: x > y)` adds an edge between the CIG nodes for the branch points that share `x` and `y`. This means:

- Contract constraints participate in treewidth estimation
- They appear in bag evaluations during DP message passing  
- They contribute to adhesion sets between bags
- Thompson Sampling's reward computation accounts for contract satisfaction

A function with strong contracts has a lower effective treewidth for its subgraph — the contract constraints reduce the free variable count in each bag, making bag evaluation faster.

---

## 5. Cross-Function Contract Propagation — Tier 4

### 5.1 Function Summary Generation

Every function with contracts generates a **symbolic summary** — a pair of (precondition formula, postcondition formula) expressed over symbolic parameter variables:

```python
@dataclass(frozen=True)
class FunctionSummary:
    function_id: str
    precondition: z3.BoolRef        # constraint on inputs
    postcondition: z3.BoolRef       # constraint on (inputs, result)
    assigns: frozenset[str]         # memory locations modified
    effect_type: EffectType         # Pure | Reads | Writes
    treewidth_contribution: int     # estimated CIG impact
```

Summaries are computed once per function and cached. When the symbolic executor encounters a call site, it instantiates the callee's summary with the current symbolic arguments rather than inlining the full function body — a massive reduction in path state size for deep call chains.

### 5.2 Summary Composition

For a call chain `f → g → h`, summaries compose:

```
f.postcondition ∧ g.precondition  →  check compatibility (Tier 4)
g.postcondition ∧ h.precondition  →  check compatibility (Tier 4)
f.postcondition ∧ h.precondition  →  transitive check (Tier 4+)
```

This is exactly where "bugs hidden for ages" get found. `f` guarantees its output is odd. `h` requires its input to be even. The contradiction `x % 2 == 1 ∧ x % 2 == 0` is UNSAT. PySyMex reports a **cross-function constraint contradiction** with the full call chain as evidence.

### 5.3 Summary Cache Architecture

```python
@dataclass
class SummaryCache:
    # Keyed by (function_id, symbolic_input_fingerprint)
    # fingerprint = hash of symbolic input constraint set
    _cache: dict[tuple[str, int], FunctionSummary]
    
    # Invalidated when contract is modified
    _version: dict[str, int]
    
    # LRU eviction for memory bound
    _lru: collections.OrderedDict[tuple[str, int], FunctionSummary]
    _max_size: int = 10_000
```

Cache hits mean the function body is never re-executed symbolically for the same abstract input class — amortized O(1) per call site for frequently-called functions with stable symbolic inputs.

---

## 6. Logical Contradiction Detection Integration

Contract constraints feed directly into the contradiction detection system:

### 6.1 Contract-Induced Contradictions

```python
@requires(lambda x: x % 2 == 0)   # x is even
def process(x: int) -> int:
    if x % 2 == 1:                 # contradicts precondition
        return x + 1               # LOGICAL_CONTRADICTION: unreachable
    return x
```

The `@requires` constraint is in the path constraint set when the branch condition `x % 2 == 1` is evaluated. The contradiction detector fires immediately — no Z3 call needed, the Tier 1 modular contradiction check catches it in O(1).

### 6.2 Pre/Postcondition Contradiction

```python
@requires(lambda x: x > 0)
@ensures(lambda result: result < 0)
def transform(x: int) -> int:
    return x * 2  # always positive given positive input
                  # contradicts @ensures result < 0
```

At `RETURN_VALUE`, the path constraints include `x > 0` (from precondition) and the concrete path constraint from the function body. The postcondition `result < 0` is checked — UNSAT given positive `x` multiplied by 2. PySyMex reports **postcondition unreachable** with the witness showing no valid input can satisfy both.

---

## 7. Full Type Signature Design

```python
from __future__ import annotations
from typing import TypeVar, Generic, Callable, ParamSpec, Concatenate
from collections.abc import Callable as CallableABC
import z3

T = TypeVar("T")
P = ParamSpec("P")
R = TypeVar("R")

# Refined type with embedded constraint
class Refined(Generic[T]):
    """Type T narrowed by predicate P."""
    __slots__ = ("_type", "_predicate", "_name", "_z3_formula")
    
    def __init__(
        self,
        base_type: type[T],
        predicate: Callable[[T], bool],
        name: str = "",
    ) -> None:
        self._type = base_type
        self._predicate = predicate
        self._name = name
        self._z3_formula: z3.BoolRef | None = None
    
    def compile(self, symbolic_var: z3.ExprRef) -> z3.BoolRef:
        """Compile predicate to Z3 formula over symbolic variable."""
        ...

# Contract decorators with full typing
def requires(
    predicate: Callable[..., bool],
    message: str = "",
    *,
    severity: Literal["ERROR", "WARNING"] = "ERROR",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Precondition contract."""
    ...

def ensures(
    predicate: Callable[Concatenate[R, P], bool],
    message: str = "",
    *,
    severity: Literal["ERROR", "WARNING"] = "ERROR",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Postcondition contract."""
    ...

def invariant(
    predicate: Callable[..., bool],
    message: str = "",
    *,
    check_on: frozenset[InjectionPoint] = frozenset({
        InjectionPoint.STORE_ATTR,
        InjectionPoint.STORE_LOCAL,
    }),
) -> Callable[[type[T]], type[T]]:
    """Class invariant contract."""
    ...

def assumes(
    predicate: Callable[..., bool],
    message: str = "",
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Assumption — asserted without proof."""
    ...

def assigns(
    *locations: str,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Frame condition — declares modifiable locations."""
    ...

def pure() -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Pure function — no side effects, enables memoization."""
    ...
```

---

## 8. Report Format

Contract violations produce a distinct report format that traces the full mathematical chain:

```
[CONTRACT_VIOLATION] divide() — Postcondition unreachable
  Location:    src/math.py:42 (RETURN_VALUE @ offset 0x18)
  Contract:    @ensures result > 0
  Path:        entry → line 38 (x < 0 branch) → line 42
  Witness:     x = -5, y = 2
  Derivation:  
    precondition:   x > 0              [from @requires, line 39]
    path constraint: x < 0             [from branch at line 38]  
    contradiction:  x > 0 ∧ x < 0     [UNSAT — Tier 1 range]
  Confidence:  EXACT (concrete witness available)

[CONTRACT_VIOLATION] process() → transform() — Cross-function contradiction  
  Location:    src/pipeline.py:87 (CALL @ offset 0x2A)
  Contract:    process.@ensures x % 2 == 1
               transform.@requires x % 2 == 0
  Contradiction: x % 2 == 1 ∧ x % 2 == 0  [UNSAT — Tier 4 modular]
  Call chain:  main() → process() → transform()
  Witness:     No valid input exists for this call sequence
  Confidence:  EXACT (mathematical proof)
```

---

## 9. Performance Properties

| Contract Type | Injection Cost | Solver Impact | Memory Impact |
|---|---|---|---|
| `@requires` | O(1) per call | Narrows path — reduces future solve cost | +1 constraint per path |
| `@ensures` | O(return_sites) | May eliminate UNSAT paths early | +1 constraint per path |
| `@invariant` | O(mutation_count) | High — checks at every mutation | +K constraints per frame |
| `@assumes` | O(1) | Reduces symbolic input space — speeds CHTD | +1 constraint permanent |
| `@assigns` | O(write_count) | Eliminates O(N²) alias queries | None — reduces AliasingAnalyzer state |
| `@pure` | O(1) | Enables memoization — amortizes to O(1) | +cache entry per call |

The `@assigns` and `@pure` contracts are the ones with the highest performance return — they don't just add constraints, they eliminate entire classes of expensive computation.

---

## 10. The Unified Picture

With this contract system fully implemented, PySyMex's detection capability becomes:

```
Without contracts:  finds bugs that are mathematically reachable
With contracts:     finds bugs that are mathematically reachable
                  + finds contradictions between what code guarantees
                    and what code assumes, across any call depth,
                    without requiring the bug to manifest as a crash
```

The mathematical foundation doesn't change. The symbolic executor doesn't change. Contracts are just precisely-typed symbolic constraints that happen to carry semantic meaning about what the programmer intended — and PySyMex checks that intention against mathematical truth automatically.