## ANTI-LAZINESS RULES — ABSOLUTE, NO EXCEPTIONS

### Forbidden Patterns
- `assert True` — ghost pass, forbidden everywhere
- `pass` — forbidden in any function, class, or test body
- `...` — forbidden as a function body or placeholder
- `# TODO`, `# FIXME`, `# implement later`, `# placeholder` — forbidden
- `raise NotImplementedError` in finished code — only allowed in Phase 1 stubs
- `Any` — forbidden. use the real type. if you do not know it, look it up in the source
- `cast()` — forbidden entirely. fix the type declaration instead
- `cast(Any, ...)` and `cast("StringLiteral", x)` — doubly forbidden, pyright cannot verify these
- `type: ignore` without an inline explanation comment — forbidden
- untyped `def` — every function must have fully annotated parameters and return type
- `-> None` on a function that returns something — forbidden
- implicit `Optional` — always explicit: `str | None`, never bare `str` with a None default
- wildcard imports: `from x import *` — forbidden
- unused imports — forbidden
- mutable default arguments: `def f(x: list = [])` — forbidden
- bare `except:` — always catch a specific exception type
- silencing pyright rules in pyrightconfig.json — forbidden. fix the code instead
- stubbing a class with only `pass` and calling it "implemented" — forbidden
- writing fewer tests than there are distinct behaviors in the source function — forbidden
- copying a test verbatim without verifying it tests what the docstring claims — forbidden

### Required Patterns
- every function has a docstring describing what it does and what it tests
- every test has exactly one clear assertion target
- every fixture has an explicit return type annotation
- every `type: ignore` has an inline comment: `# type: ignore[assignment]  # Linux-only API, no stub available`
- pyright --strict must pass before any task is reported as done
- if a type is complex, define a TypeAlias or TypedDict — do not flatten it to Any
- if setup logic is needed, use the real classes from pysymex/ — do not mock what already exists

## REPORTING RULES
- never stop to report progress between files
- never summarize what you just did and wait
- never treat completing one file as a milestone worth pausing at
- the only permitted report is the final completion report when ALL files are done
- intermediate "I completed X" summaries are forbidden — they waste tokens and cost money
- after finishing any file, immediately start the next one without any output between them

## EXECUTION RULES
- never announce what you are about to do — execute it immediately
- never emit a plan and stop — a plan is only valid if followed by immediate execution
- never ask for confirmation between files or steps unless a fatal unrecoverable error occurs
- never collapse multiple test methods into one monolithic function — one method per behavior, always
- never delete an existing stub and replace it with a merged function — restore and populate instead
- never treat a single file completion as a stopping condition
- compact context and continue if you approach context limits — stopping is not permitted
- all file edits in this session are pre-authorized — do not prompt for permission

## TEST STRUCTURE RULES
- one test class per source class — mirror the source structure exactly
- one test method per distinct behavior — never merge behaviors into one function
- if a source function has 5 distinct behaviors, write 5 separate test methods
- never merge test_extend, test_pop, test_insert etc. into one test_list_operations — ever
- every test class must have the same number of methods as there are distinct behaviors in the source
- a monolithic test that covers multiple behaviors is an automatic failure regardless of assertions

## PYRIGHT RULES
- always run pyright using: pyright -p pyrightconfig_tests.json <file>
- never use pyrightconfig.json rule silencing to bypass errors — fix the code instead
- never add rules set to "none" in any pyrightconfig file to work around failures
- zero errors is the only acceptable pyright exit state
- unused imports are a pyright error — remove them before reporting done

## COST AWARENESS
- every unnecessary pause, summary, or confirmation prompt wastes tokens and money
- the goal is maximum work per token spent — silence between files is free, summaries are not
- do not output anything between completing one file and starting the next

## GHOST PASS DETECTION — FORBIDDEN ASSERTION PATTERNS
any assertion that is always true by construction is a ghost pass and forbidden:
- `assert True`
- `assert __name__ != ""`
- `assert 1 == 1`
- `assert result is not None` when result can never be None by construction
- `assert len(x) >= 0` — length is never negative
- `assert isinstance(x, type(x))` — always true
- `_assert_behavior()` or any shared assertion helper — forbidden
- `assert x == x` — tautology, forbidden

## HARDWARE-DEPENDENT TEST RULES
- every test touching CuPy, CUDA, or GPU must have:
  `@pytest.mark.skipif(not cupy_available, reason="CUDA required")`
- every test touching Numba JIT must verify correctness on at least 3 bit widths
- never mock the CPU backend — it must be tested with real Numba execution
- GPU backend may be mocked ONLY when CUDA is physically unavailable

## KNOWN CRITICAL BEHAVIORS — MUST BE EXPLICITLY TESTED
these specific bugs were found in accel/ and must have dedicated regression tests:
- np.unpackbits bit-order mismatch: test both LSB and MSB, assert correct output for each
- solve_bag returning count=0 for satisfiable input: assert count > 0 for known-SAT bags
- CHTD iteration counter stalling: assert counter increments on every fork
- wide bag silent UNSAT for w>12: assert solve_bag handles w=13, w=16, w=32 correctly
- these tests must exist and must pass — they are non-negotiable

## FIXTURE RULES
- shared fixtures via `_make_x()` helpers are allowed ONLY when the constructor
  genuinely requires external dependencies (like ConstraintIndependenceOptimizer)
- shared fixtures that exist purely to avoid writing setup code are forbidden
- every fixture must have an explicit return type annotation
- conftest.py fixtures must be typed with explicit return types — no implicit Any

## SKIP VS XFAIL
- `@pytest.mark.skip` — forbidden unless hardware is physically absent
- `@pytest.mark.xfail(strict=True, reason="known bug: <description>")` — use for known bugs
- never delete a failing test — mark it xfail with a precise description instead

## VERSION-SPECIFIC TEST RULES
- opcodes/py311/, opcodes/py312/, opcodes/py313/ must each
  have completely separate test files
- never merge version-specific opcode behavior into a shared test
- every version-specific test must assert the exact divergent
  behavior for that Python version
- if an opcode behaves identically across versions, test it
  in base/ only — do not duplicate

## VM AND BYTECODE TEST RULES
- never mock the VM loop — always use real bytecode
- real bytecode must be compiled via:
  `code = compile("x = 1 + 2", "<test>", "exec")`
- never hand-craft instruction sequences — always compile
  from real Python source
- symbolic inputs to the VM must be real Z3 expressions
  injected into the initial VM state — never mocked

## EXECUTOR TEST RULES
- async executors must use real asyncio event loops
- never mock asyncio.get_event_loop() or asyncio.run()
- concurrent executors must use real threading —
  never mock Thread or Lock
- verified executor must assert soundness: same input
  must produce same output across multiple runs
- facade must be tested through its public API only —
  never access internal executor state directly

## ASYNC TEST RULES
- every async test must use @pytest.mark.asyncio
- every async test must have @pytest.mark.timeout(30)
- never use asyncio.run() inside a test — use pytest-asyncio
- always await coroutines — never fire and forget in tests
- event loop must never be shared between tests —
  use function-scoped event loop fixture

## TERMINATION TEST RULES
- termination.py must be tested with:
  1. a path that terminates in finite steps
  2. a path that hits the step limit
  3. a symbolic path where termination is undecidable
- never assert that a non-terminating path completes —
  assert that it hits the termination boundary correctly

## FORBIDDEN EXECUTION PATTERNS
- never mock the Python VM or bytecode interpreter
- never mock Z3 solver calls in execution tests
- never use time.sleep() to simulate async behavior
- never use threading.Event() as a substitute for
  real concurrent execution
- never test opcode handlers in isolation without
  a real VM state object