# pysymex API Reference

Complete Python API reference for pysymex symbolic execution engine.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Main Functions](#main-functions)
3. [Scanner Functions](#scanner-functions)
4. [Core Classes](#core-classes)
5. [Configuration](#configuration)
6. [Issue Types](#issue-types)
7. [Advanced Usage](#advanced-usage)

---

## Quick Start

```python
from pysymex import analyze, scan_file, scan_directory

# Analyze a function
def divide(x, y):
    return x / y

result = analyze(divide)
for issue in result.issues:
    print(issue.format())

# Scan a file
result = scan_file("mycode.py")
print(f"Found {len(result.issues)} issues")

# Scan a directory
results = scan_directory("./src")
```

---

## Main Functions

### analyze()

The primary entry point for analyzing Python functions.

```python
from pysymex import analyze

result = analyze(
    func,                           # Function to analyze
    symbolic_args=None,             # Dict of param name -> type
    *,
    max_paths=1000,                 # Max paths to explore
    max_depth=100,                  # Max recursion depth
    max_iterations=10000,           # Max iterations
    timeout=60.0,                   # Timeout in seconds
    verbose=False,                  # Print verbose output
    detect_division_by_zero=True,   # Check for div/0
    detect_assertion_errors=True,   # Check for assertions
    detect_index_errors=True,       # Check for index OOB
    detect_type_errors=True,        # Check for type mismatches
    detect_overflow=False,          # Check for overflow
) -> ExecutionResult
```

**Parameters:**
- `func` (Callable): The function to analyze
- `symbolic_args` (Dict[str, str], optional): Mapping of parameter names to types
  - Supported types: `"int"`, `"str"`, `"list"`, `"bool"`, `"dict"`
  - Default: all parameters treated as `"int"`

**Returns:** `ExecutionResult` object with analysis results

**Example:**
```python
def process(items, index):
    return items[index]

# Specify types for parameters
result = analyze(
    process, 
    symbolic_args={"items": "list", "index": "int"},
    detect_index_errors=True
)

if result.has_issues():
    for issue in result.issues:
        print(issue.format())
```

---

### analyze_code()

Analyze a code snippet string.

```python
from pysymex import analyze_code

code = """
def foo(x, y):
    return x / y
"""

result = analyze_code(
    code,                    # Python source code
    symbolic_vars=None,      # Dict of var name -> type
    **kwargs                 # Same options as analyze()
)
```

**Example:**
```python
code = """
def risky(x):
    if x > 0:
        return 100 / x
    return 0
"""

result = analyze_code(code, {"x": "int"})
print(f"Issues: {len(result.issues)}")
```

---

### analyze_file()

Analyze a specific function from a Python file.

```python
from pysymex import analyze_file

result = analyze_file(
    filepath,           # Path to Python file
    function_name,      # Name of function to analyze
    symbolic_args=None, # Dict of param name -> type
    **kwargs            # Same options as analyze()
)
```

**Example:**
```python
# Analyze the 'calculate' function from utils.py
result = analyze_file(
    "utils.py",
    "calculate",
    {"a": "int", "b": "int"}
)
```

---

### quick_check()

Quick check a function with default settings.

```python
from pysymex import quick_check

issues = quick_check(func) -> List[Issue]
```

**Example:**
```python
issues = quick_check(lambda x: 1 / x)
if issues:
    print(f"Found {len(issues)} potential issues")
```

---

### Specific Checks

```python
from pysymex import (
    check_division_by_zero,
    check_assertions,
    check_index_errors,
)

# Check only for division by zero
issues = check_division_by_zero(func) -> List[Issue]

# Check only for assertion errors
issues = check_assertions(func) -> List[Issue]

# Check only for index errors
issues = check_index_errors(func) -> List[Issue]
```

---

## Scanner Functions

### scan_file()

Scan a single Python file for all potential bugs.

```python
from pysymex import scan_file

result = scan_file(
    file_path,          # Path to Python file
    verbose=False,      # Print output
    max_paths=100,      # Max paths per function
    timeout=30.0        # Timeout in seconds
) -> ScanResult
```

**Returns:** `ScanResult` object

**Example:**
```python
result = scan_file("mycode.py")

print(f"File: {result.file_path}")
print(f"Issues: {len(result.issues)}")
print(f"Code objects: {result.code_objects}")
print(f"Paths explored: {result.paths_explored}")

for issue in result.issues:
    print(f"[{issue['kind']}] Line {issue['line']}: {issue['message']}")
```

---

### scan_directory()

Scan all Python files in a directory.

```python
from pysymex import scan_directory

results = scan_directory(
    dir_path,               # Directory path
    pattern="**/*.py",      # Glob pattern
    verbose=True,           # Show progress
    max_paths=100,          # Max paths per function
    timeout=30.0            # Timeout per file
) -> List[ScanResult]
```

**Example:**
```python
results = scan_directory("./src", verbose=True)

total_issues = sum(len(r.issues) for r in results)
print(f"Total issues across all files: {total_issues}")
```

---

## Core Classes

### ExecutionResult

Result of symbolic execution analysis.

```python
class ExecutionResult:
    issues: List[Issue]             # Issues found
    paths_explored: int             # Number of paths
    execution_time: float           # Time taken
    coverage: CoverageInfo          # Coverage data
    
    def has_issues(self) -> bool:
        """Check if any issues were found."""
    
    def get_issues_by_kind(self, kind: IssueKind) -> List[Issue]:
        """Filter issues by type."""
```

---

### Issue

Represents a potential bug found during analysis.

```python
class Issue:
    kind: IssueKind                 # Type of issue
    message: str                    # Human-readable message
    line_number: int                # Source line (1-based)
    pc: int                         # Bytecode offset
    path_constraints: List          # Z3 constraints
    
    def format(self) -> str:
        """Format issue as human-readable string."""
    
    def get_counterexample(self) -> Dict[str, Any]:
        """Get variable values that trigger this bug."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON."""
```

---

### ScanResult

Result of scanning a file with the scanner module.

```python
@dataclass
class ScanResult:
    file_path: str                  # Path to file
    timestamp: str                  # ISO timestamp
    issues: List[Dict[str, Any]]    # Issues as dicts
    code_objects: int               # Functions/classes
    paths_explored: int             # Paths analyzed
    error: str                      # Error or None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON."""
```

---

### SymbolicValue

Core symbolic value class.

```python
class SymbolicValue:
    """Represents a symbolic value that can be concrete or symbolic."""
    
    @staticmethod
    def symbolic(name: str) -> SymbolicValue:
        """Create a new symbolic variable."""
    
    @staticmethod
    def from_const(value: Any) -> SymbolicValue:
        """Create from a concrete value."""
```

---

### SymbolicExecutor

The main execution engine.

```python
class SymbolicExecutor:
    def __init__(self, config: ExecutionConfig = None):
        """Initialize executor with configuration."""
    
    def execute_function(
        self, 
        func: Callable, 
        symbolic_args: Dict[str, str] = None
    ) -> ExecutionResult:
        """Execute a function symbolically."""
    
    def execute_code(
        self,
        code: CodeType,
        symbolic_vars: Dict[str, str] = None
    ) -> ExecutionResult:
        """Execute a code object symbolically."""
```

---

## Configuration

### ExecutionConfig

Configure the symbolic execution engine.

```python
from pysymex import ExecutionConfig

config = ExecutionConfig(
    max_paths=1000,              # Max paths to explore
    max_depth=100,               # Max call/recursion depth
    max_iterations=10000,        # Max loop iterations
    timeout_seconds=60.0,        # Timeout
    verbose=False,               # Verbose output
    
    # Detector toggles
    detect_division_by_zero=True,
    detect_assertion_errors=True,
    detect_index_errors=True,
    detect_type_errors=True,
    detect_overflow=False,
)
```

---

### PysymexConfig

Load configuration from file.

```python
from pysymex import PysymexConfig, load_config

# Load from pysymex.toml in current directory
config = load_config()

# Or specify path
config = load_config("example_config.toml")
```

**Config file format (pysymex.toml):**

```toml
[execution]
max_paths = 1000
max_depth = 100
max_iterations = 10000
timeout_seconds = 60.0
verbose = false

[detectors]
division_by_zero = true
assertion_errors = true
index_errors = true
type_errors = true
null_dereference = true

[output]
format = "text"
```

---

### Logging Configuration

```python
from pysymex import configure_logging, LogLevel

# Set log level
configure_logging(LogLevel.DEBUG)
configure_logging(LogLevel.INFO)
configure_logging(LogLevel.WARNING)
configure_logging(LogLevel.ERROR)
```

---

## Issue Types

### IssueKind Enum

```python
from pysymex import IssueKind

class IssueKind(Enum):
    DIVISION_BY_ZERO = "DIVISION_BY_ZERO"
    ASSERTION_ERROR = "ASSERTION_ERROR"
    INDEX_ERROR = "INDEX_ERROR"
    KEY_ERROR = "KEY_ERROR"
    TYPE_ERROR = "TYPE_ERROR"
    ATTRIBUTE_ERROR = "ATTRIBUTE_ERROR"
    NULL_DEREFERENCE = "NULL_DEREFERENCE"
    FORMAT_STRING_ERROR = "FORMAT_STRING_ERROR"
    RESOURCE_LEAK = "RESOURCE_LEAK"
    OVERFLOW = "OVERFLOW"
    UNREACHABLE_CODE = "UNREACHABLE_CODE"
    INFINITE_LOOP = "INFINITE_LOOP"
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"
    VALUE_ERROR = "VALUE_ERROR"
    UNBOUND_VARIABLE = "UNBOUND_VARIABLE"
    UNHANDLED_EXCEPTION = "UNHANDLED_EXCEPTION"
    RECURSION_LIMIT = "RECURSION_LIMIT"
```

### Issue Descriptions

| Kind | Description | Example Code |
|------|-------------|--------------|
| `DIVISION_BY_ZERO` | Division where denominator can be 0 | `x / y` when y=0 |
| `INDEX_ERROR` | List access out of bounds | `arr[i]` when i<0 or i>=len |
| `KEY_ERROR` | Dict key not found | `d[key]` when key missing |
| `TYPE_ERROR` | Type mismatch | `"str" + 5` |
| `NULL_DEREFERENCE` | Accessing None | `x.method()` when x=None |
| `ASSERTION_ERROR` | Assert can fail | `assert x > 0` when x=0 |
| `FORMAT_STRING_ERROR` | Bad format string | `"{} {}".format(x)` |
| `RESOURCE_LEAK` | Unclosed resource | `open(f)` without close |
| `VALUE_ERROR` | Invalid arguments to builtins | `int("abc")` |
| `UNBOUND_VARIABLE` | Accessing variable before assignment | `print(x)` before `x = 1` |

---

## Advanced Usage

### Custom Detectors

```python
from pysymex.analysis.detectors import BaseDetector, Issue, IssueKind
from pysymex.core.state import VMState

class CustomDetector(BaseDetector):
    """Custom detector for specific patterns."""
    
    def check_state(self, state: VMState) -> List[Issue]:
        issues = []
        # Custom detection logic here
        return issues
```

### Verified Execution

For formal verification with contracts:

```python
from pysymex import (
    verify,
    check_contracts,
    check_arithmetic,
    prove_termination,
)

# Verify a function meets its contract
result = verify(
    func,
    preconditions=["x > 0", "y > 0"],
    postconditions=["result > 0"]
)

# Check arithmetic properties
result = check_arithmetic(func)

# Attempt to prove termination
result = prove_termination(func)
```

### Inter-Procedural Analysis

Analyze call graphs:

```python
from pysymex.analysis.interprocedural import CallGraphAnalyzer

analyzer = CallGraphAnalyzer()
call_graph = analyzer.build_call_graph(module)

# Find all paths from entry to sensitive sinks
paths = analyzer.find_paths_to_sink("sensitive_function")
```

---

## Module Exports

All public exports from `pysymex`:

```python
from pysymex import (
    # Main API
    analyze,
    analyze_file,
    analyze_code,
    quick_check,

    # Async API
    analyze_async,
    analyze_code_async,
    analyze_file_async,

    # Specific checks
    check_division_by_zero,
    check_assertions,
    check_index_errors,

    # Scanner
    scan_file,
    scan_directory,
    scan_directory_async,

    # Core classes
    SymbolicExecutor,
    ExecutionConfig,
    ExecutionResult,
    SymbolicValue,
    SymbolicString,
    SymbolicList,
    SymbolicDict,
    SymbolicObject,
    SymbolicNone,
    VMState,
    ShadowSolver,

    # Z3 engine (high-level API)
    Z3Engine,
    Z3Prover,          # alias for Z3Engine
    CallGraph,
    FunctionSummary,
    BugType,
    Severity,
    VerificationResult,
    CrashCondition,
    verify_function,
    verify_code,
    z3_verify_file,
    z3_verify_directory,
    is_z3_available,

    # Analysis
    Issue,
    IssueKind,

    # Configuration
    PysymexConfig,
    load_config,
    configure_logging,
    get_logger,
    LogLevel,

    # Utilities
    format_issues,
    format_result,

    # Verified execution
    VerifiedExecutor,
    VerifiedExecutionConfig,
    VerifiedExecutionResult,
    verify,
    check_contracts,
    check_arithmetic,
    prove_termination,
)
```

---

## See Also

- [CLI Guide](CLI.md) - Command-line interface
- [Scanner Guide](SCANNER.md) - File and directory scanning
- [Examples](../examples/) - Code examples
