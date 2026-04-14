# PySyMex Internal Tracing Enhancement Plan

## Executive Summary

This plan outlines the implementation of an enhanced internal tracing system for PySyMex that enables extreme depth analysis, LLM-driven optimization, and silent bug detection. The system builds on the existing tracing infrastructure and adds automatic instrumentation, schema generation, and data pool aggregation.

**Vision**: `@trace("category")` decorator for PySyMex-internal use only, enabling automatic data capture and analysis.

**Timeline**: 3-4 weeks for full implementation
**Priority**: Medium (Phase 2 after core improvements)

---

## Phase 1: Core Decorator System (Week 1)

### 1.1 Decorator Implementation

**File**: `pysymex/tracing/decorator.py`

```python
from functools import wraps
from typing import Callable, Any, ParamSpec, TypeVar
from dataclasses import dataclass
import inspect

P = ParamSpec('P')
T = TypeVar('T')

@dataclass(frozen=True)
class TracePoint:
    """Metadata for a traced function."""
    category: str
    function_name: str
    module: str
    line_number: int
    signature: str

class TraceRegistry:
    """Registry for all @trace decorated functions."""
    _instances: dict[str, TracePoint] = {}
    
    @classmethod
    def register(cls, trace_point: TracePoint) -> None:
        cls._instances[f"{trace_point.module}.{trace_point.function_name}"] = trace_point
    
    @classmethod
    def get_all(cls) -> list[TracePoint]:
        return list(cls._instances.values())
    
    @classmethod
    def get_by_category(cls, category: str) -> list[TracePoint]:
        return [tp for tp in cls._instances.values() if tp.category == category]

def trace(category: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator for internal PySyMex tracing.
    
    Args:
        category: Tracing category (e.g., "constraint_solving", "state_forking")
    
    Usage:
        @trace("constraint_solving")
        def solve_constraints(constraints):
            ...
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        # Get function metadata
        frame = inspect.currentframe()
        module = inspect.getmodule(func).__name__
        line = frame.f_back.f_lineno if frame else 0
        
        # Create trace point
        trace_point = TracePoint(
            category=category,
            function_name=func.__name__,
            module=module,
            line_number=line,
            signature=str(inspect.signature(func))
        )
        
        # Register
        TraceRegistry.register(trace_point)
        
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Capture pre-execution state
            pre_state = _capture_state(func, args, kwargs)
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Capture post-execution state
            post_state = _capture_state(func, args, kwargs, result)
            
            # Emit trace event
            _emit_trace_event(trace_point, pre_state, post_state)
            
            return result
        
        return wrapper
    return decorator
```

### 1.2 State Capture System

**File**: `pysymex/tracing/capture.py`

```python
from typing import Any, Dict
import inspect
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue

def _capture_state(func: Callable, args: tuple, kwargs: dict, result: Any = None) -> dict:
    """Capture state before/after function execution."""
    state = {
        'timestamp': time.time(),
        'args': _serialize_args(args),
        'kwargs': _serialize_kwargs(kwargs),
    }
    
    if result is not None:
        state['result'] = _serialize_value(result)
    
    # Capture VMState if present
    for arg in args:
        if isinstance(arg, VMState):
            state['vm_state'] = _capture_vm_state(arg)
            break
    
    return state

def _capture_vm_state(state: VMState) -> dict:
    """Capture VMState snapshot."""
    return {
        'pc': state.pc,
        'stack_depth': len(state.stack),
        'local_vars_count': len(state.local_vars),
        'path_constraints_count': len(state.path_constraints.to_list()),
        'symbolic_vars': _extract_symbolic_vars(state),
    }

def _extract_symbolic_vars(state: VMState) -> dict:
    """Extract symbolic variable information."""
    symbolic_vars = {}
    for name, value in state.local_vars.items():
        if isinstance(value, SymbolicValue):
            symbolic_vars[name] = {
                'type': 'int' if value.z3_int is not None else 'bool',
                'has_constraint': True,
            }
    return symbolic_vars
```

---

## Phase 2: Automatic Schema Generation (Week 1-2)

### 2.1 Schema Inference Engine

**File**: `pysymex/tracing/schema_gen.py`

```python
from typing import Dict, Any, Type
import inspect
from dataclasses import is_dataclass
from pydantic import BaseModel, create_model

class SchemaGenerator:
    """Automatically generate schemas from traced functions."""
    
    def __init__(self):
        self._schemas: dict[str, type[BaseModel]] = {}
    
    def generate_schema(self, trace_point: TracePoint) -> type[BaseModel]:
        """Generate Pydantic schema for a trace point."""
        func = self._get_function(trace_point)
        signature = inspect.signature(func)
        
        # Build field definitions
        fields = {}
        for param_name, param in signature.parameters.items():
            fields[param_name] = (self._infer_type(param), ...)
        
        # Add metadata fields
        fields.update({
            'timestamp': (float, ...),
            'category': (str, ...),
            'function_name': (str, ...),
        })
        
        # Create model
        schema = create_model(
            f"{trace_point.function_name}_Trace",
            __config__=type('Config', (), {'frozen': True}),
            **fields
        )
        
        self._schemas[trace_point.function_name] = schema
        return schema
    
    def _infer_type(self, param: inspect.Parameter) -> type:
        """Infer type from parameter annotation or default value."""
        if param.annotation != inspect.Parameter.empty:
            return param.annotation
        if param.default is not None:
            return type(param.default)
        return Any
    
    def _get_function(self, trace_point: TracePoint) -> Callable:
        """Get function object from trace point."""
        # Implementation: import module and get function
        module = importlib.import_module(trace_point.module)
        return getattr(module, trace_point.function_name)
```

### 2.2 Dynamic Event Registration

**File**: `pysymex/tracing/dynamic_events.py`

```python
from pysymex.tracing.schemas import TraceEvent
from pydantic import TypeAdapter

class DynamicEventRegistry:
    """Registry for dynamically generated trace events."""
    
    def __init__(self):
        self._adapters: dict[str, TypeAdapter] = {}
    
    def register_schema(self, schema_name: str, schema: type[BaseModel]) -> None:
        """Register a dynamic schema."""
        self._adapters[schema_name] = TypeAdapter(schema)
    
    def serialize_event(self, schema_name: str, data: dict) -> str:
        """Serialize event using registered schema."""
        adapter = self._adapters.get(schema_name)
        if adapter:
            return adapter.validate_python(data).model_dump_json()
        return json.dumps(data)
```

---

## Phase 3: Data Pool Aggregation (Week 2)

### 3.1 Data Pool Storage

**File**: `pysymex/tracing/pool.py`

```python
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Any
from datetime import datetime
import sqlite3
from pathlib import Path

@dataclass
class TraceRecord:
    """Single trace record."""
    id: str
    timestamp: datetime
    category: str
    function_name: str
    data: dict
    metadata: dict = field(default_factory=dict)

class DataPool:
    """Centralized data pool for trace aggregation."""
    
    def __init__(self, db_path: str = ".pysymex/traces/pool.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize SQLite database."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traces (
                id TEXT PRIMARY KEY,
                timestamp DATETIME,
                category TEXT,
                function_name TEXT,
                data JSON,
                metadata JSON
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON traces(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_function ON traces(function_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON traces(timestamp)")
        conn.commit()
        conn.close()
    
    def add_record(self, record: TraceRecord) -> None:
        """Add trace record to pool."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO traces (id, timestamp, category, function_name, data, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.timestamp.isoformat(),
                record.category,
                record.function_name,
                json.dumps(record.data),
                json.dumps(record.metadata)
            )
        )
        conn.commit()
        conn.close()
    
    def query_by_category(self, category: str) -> List[TraceRecord]:
        """Query records by category."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT * FROM traces WHERE category = ? ORDER BY timestamp DESC",
            (category,)
        )
        records = [self._row_to_record(row) for row in cursor.fetchall()]
        conn.close()
        return records
    
    def query_by_function(self, function_name: str) -> List[TraceRecord]:
        """Query records by function name."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT * FROM traces WHERE function_name = ? ORDER BY timestamp DESC",
            (function_name,)
        )
        records = [self._row_to_record(row) for row in cursor.fetchall()]
        conn.close()
        return records
    
    def _row_to_record(self, row) -> TraceRecord:
        """Convert database row to TraceRecord."""
        return TraceRecord(
            id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            category=row[2],
            function_name=row[3],
            data=json.loads(row[4]),
            metadata=json.loads(row[5])
        )
```

### 3.2 Pool Query Interface

**File**: `pysymex/tracing/query.py`

```python
from typing import List, Dict, Any, Optional
from pysymex.tracing.pool import DataPool, TraceRecord

class PoolQuery:
    """Query interface for data pool."""
    
    def __init__(self, pool: DataPool):
        self.pool = pool
    
    def get_all_categories(self) -> List[str]:
        """Get all unique categories."""
        conn = sqlite3.connect(self.pool.db_path)
        cursor = conn.execute("SELECT DISTINCT category FROM traces")
        categories = [row[0] for row in cursor.fetchall()]
        conn.close()
        return categories
    
    def get_category_stats(self, category: str) -> Dict[str, Any]:
        """Get statistics for a category."""
        records = self.pool.query_by_category(category)
        return {
            'count': len(records),
            'functions': len(set(r.function_name for r in records)),
            'time_range': (
                min(r.timestamp for r in records),
                max(r.timestamp for r in records)
            ) if records else None
        }
    
    def find_anomalies(self, category: str, threshold: float = 2.0) -> List[TraceRecord]:
        """Find anomalous records based on execution time."""
        records = self.pool.query_by_category(category)
        # Simple anomaly detection: outliers in duration
        # Implementation: statistical analysis
        return []
```

---

## Phase 4: Integration with Existing Tracing (Week 2-3)

### 4.1 Enhanced ExecutionTracer

**File**: `pysymex/tracing/tracer_enhanced.py`

```python
from pysymex.tracing.tracer import ExecutionTracer
from pysymex.tracing.pool import DataPool, TraceRecord
from pysymex.tracing.decorator import TraceRegistry
import uuid
from datetime import datetime

class EnhancedExecutionTracer(ExecutionTracer):
    """Enhanced tracer with data pool integration."""
    
    def __init__(self, config: TracerConfig):
        super().__init__(config)
        self.data_pool = DataPool()
        self._decorator_hooks_enabled = True
    
    def emit_decorator_trace(self, trace_point, pre_state, post_state) -> None:
        """Emit trace from @trace decorator."""
        record = TraceRecord(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            category=trace_point.category,
            function_name=trace_point.function_name,
            data={
                'pre': pre_state,
                'post': post_state,
            },
            metadata={
                'module': trace_point.module,
                'line_number': trace_point.line_number,
                'signature': trace_point.signature,
            }
        )
        self.data_pool.add_record(record)
```

### 4.2 Hook Integration

**File**: `pysymex/tracing/integration.py`

```python
from pysymex.tracing.decorator import TraceRegistry
from pysymex.tracing.schema_gen import SchemaGenerator
from pysymex.tracing.dynamic_events import DynamicEventRegistry

def setup_enhanced_tracing() -> None:
    """Setup enhanced tracing system."""
    # Register all @trace decorated functions
    trace_points = TraceRegistry.get_all()
    
    # Generate schemas for all trace points
    schema_gen = SchemaGenerator()
    event_registry = DynamicEventRegistry()
    
    for tp in trace_points:
        schema = schema_gen.generate_schema(tp)
        event_registry.register_schema(tp.function_name, schema)
    
    print(f"Enhanced tracing setup complete: {len(trace_points)} trace points registered")
```

---

## Phase 5: Analysis and Visualization (Week 3-4)

### 5.1 Analysis Engine

**File**: `pysymex/tracing/analysis.py`

```python
from pysymex.tracing.pool import DataPool
from pysymex.tracing.query import PoolQuery
import statistics

class TraceAnalyzer:
    """Analyze trace data for insights."""
    
    def __init__(self, pool: DataPool):
        self.pool = pool
        self.query = PoolQuery(pool)
    
    def analyze_performance(self, category: str) -> dict:
        """Analyze performance metrics for a category."""
        records = self.pool.query_by_category(category)
        
        # Extract durations from timestamps
        durations = []
        for i in range(1, len(records)):
            duration = (records[i].timestamp - records[i-1].timestamp).total_seconds()
            durations.append(duration)
        
        return {
            'count': len(records),
            'mean_duration': statistics.mean(durations) if durations else 0,
            'median_duration': statistics.median(durations) if durations else 0,
            'min_duration': min(durations) if durations else 0,
            'max_duration': max(durations) if durations else 0,
        }
    
    def detect_patterns(self, category: str) -> list:
        """Detect patterns in trace data."""
        # Pattern detection logic
        # - Repeated sequences
        # - State transitions
        # - Constraint dependencies
        return []
```

### 5.2 CLI Tool

**File**: `pysymex/tracing/cli.py`

```python
import argparse
from pysymex.tracing.pool import DataPool
from pysymex.tracing.query import PoolQuery
from pysymex.tracing.analysis import TraceAnalyzer

def main():
    parser = argparse.ArgumentParser(description="PySyMex enhanced tracing CLI")
    parser.add_argument("action", choices=["list", "analyze", "query"])
    parser.add_argument("--category", help="Filter by category")
    parser.add_argument("--function", help="Filter by function name")
    parser.add_argument("--db", default=".pysymex/traces/pool.db", help="Database path")
    
    args = parser.parse_args()
    
    pool = DataPool(args.db)
    query = PoolQuery(pool)
    analyzer = TraceAnalyzer(pool)
    
    if args.action == "list":
        categories = query.get_all_categories()
        for cat in categories:
            stats = query.get_category_stats(cat)
            print(f"{cat}: {stats['count']} records, {stats['functions']} functions")
    
    elif args.action == "analyze":
        if args.category:
            metrics = analyzer.analyze_performance(args.category)
            print(json.dumps(metrics, indent=2))
    
    elif args.action == "query":
        if args.category:
            records = pool.query_by_category(args.category)
            for r in records[:10]:  # Limit to 10
                print(f"{r.timestamp} - {r.function_name}")

if __name__ == "__main__":
    main()
```

---

## Implementation Order

### Week 1
1. Implement `@trace` decorator system
2. Implement state capture system
3. Implement schema generation engine
4. Unit tests for decorator and schema gen

### Week 2
1. Implement data pool storage (SQLite)
2. Implement query interface
3. Integrate with existing ExecutionTracer
4. Integration tests

### Week 3
1. Implement analysis engine
2. Implement CLI tool
3. Add visualization hooks (JSON export)
4. End-to-end tests

### Week 4
1. LLM integration hooks (structured output)
2. Performance optimization
3. Documentation
4. Final testing and validation

---

## Usage Examples

### Basic Usage

```python
from pysymex.tracing import trace

@trace("constraint_solving")
def solve_constraints(constraints):
    # Implementation
    pass

@trace("state_forking")
def fork_state(state):
    # Implementation
    pass
```

### Querying Data

```bash
# List all categories
python -m pysymex.tracing.cli list

# Analyze performance
python -m pysymex.tracing.cli analyze --category constraint_solving

# Query specific category
python -m pysymex.tracing.cli query --category state_forking
```

### Programmatic Access

```python
from pysymex.tracing.pool import DataPool
from pysymex.tracing.query import PoolQuery

pool = DataPool()
query = PoolQuery(pool)

# Get all constraint_solving records
records = pool.query_by_category("constraint_solving")

# Get statistics
stats = query.get_category_stats("constraint_solving")
```

---

## Architecture Benefits

1. **Minimal Intrusion**: Decorator-based, non-invasive
2. **Automatic**: Schema generation and data capture are automatic
3. **Internal-Only**: Designed for PySyMex development, not external use
4. **Scalable**: SQLite pool handles large datasets
5. **Queryable**: Rich query interface for analysis
6. **LLM-Ready**: Structured data suitable for LLM consumption

---

## Future Enhancements

1. **Real-time Dashboard**: Web UI for live trace monitoring
2. **ML Anomaly Detection**: Machine learning for pattern detection
3. **Distributed Pool**: Support for distributed tracing
4. **Performance Profiling**: Advanced profiling metrics
5. **LLM Integration**: Direct LLM API for automated analysis

---

## Conclusion

This plan provides a comprehensive path to implementing the enhanced tracing system. The system builds on the existing tracing infrastructure, adds automatic instrumentation, and enables deep analysis for LLM-driven optimization. The implementation is modular and can be phased in over 3-4 weeks.
