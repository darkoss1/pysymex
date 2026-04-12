# PySyMex: Hardware Acceleration Coverage & Propagation Analyzer
# -------------------------------------------------------------
# This script performs "Smart Analysis" of the accel/ module integration.
# It identifies:
# 1. Reached Paths: Actual calls to accelerated kernels.
# 2. Ghost Paths: Config flags that propagate but never trigger acceleration.
# 3. Bottlenecks: Modules with heavy Boolean logic not yet using accel/.

import ast
import os
from pathlib import Path

class AccelMapper(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.uses_accel = False
        self.accel_calls = []
        self.config_hooks = []
        self.current_function = "module"
        
        # Accel "Sensors" - Functions that indicate hardware execution
        self.target_functions = {
            "evaluate_bag", "evaluate_bag_async", "evaluate_bag_projected",
            "propagate_all", "compile_constraint", "create_gpu_bag_solver",
            "is_available", "get_dispatcher"
        }
        
        # Config "Hooks" - Variables that should trigger acceleration
        self.target_flags = {
            "use_h_acceleration", "use_chtd", "enable_h_acceleration",
            "h_acceleration", "chtd", "config", "ExecutionConfig"
        }

    def visit_FunctionDef(self, node):
        old_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_func

    def visit_AsyncFunctionDef(self, node):
        old_func = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_func

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
        if func_name in self.target_functions:
            self.uses_accel = True
            self.accel_calls.append({
                "function": func_name,
                "line": node.lineno,
                "context": self.current_function
            })
        self.generic_visit(node)

    def visit_Name(self, node):
        if node.id in self.target_flags:
            self.config_hooks.append({
                "flag": node.id,
                "line": node.lineno,
                "context": self.current_function
            })
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in self.target_flags:
            self.config_hooks.append({
                "flag": node.attr,
                "line": node.lineno,
                "context": self.current_function
            })
        self.generic_visit(node)

def analyze_project(root_dir: str):
    print(f"\nPySyMex Accel Mapping System")
    print("=" * 60)
    
    report = {
        "reached": [],
        "ghost_hooks": [],
        "untapped": []
    }
    
    # Path patterns that are high-priority targets for acceleration
    high_priority_patterns = [
        "pysymex/execution/opcodes",
        "pysymex/scanner",
        "pysymex/analysis/detectors",
        "pysymex/core/solver"
    ]
    
    # FOCUS: Only scan the actual source code in pysymex/
    source_dir = Path(root_dir) / "pysymex"
    files_to_scan = list(source_dir.rglob("*.py"))
    
    for py_file in files_to_scan:
        file_str = str(py_file).replace("\\", "/")
        
        # Internal accel files are the "Provider", so we skip them to find the "Consumers"
        if "/accel/" in file_str:
            continue
            
        try:
            with open(py_file, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
                
            mapper = AccelMapper(file_str)
            mapper.visit(tree)
            
            rel_path = os.path.relpath(py_file, root_dir).replace("\\", "/")
            
            if mapper.accel_calls:
                report["reached"].append({
                    "path": rel_path,
                    "calls": mapper.accel_calls
                })
            
            # Smart Detection: Flag exists but no accel call in the same file
            if mapper.config_hooks and not mapper.accel_calls:
                # Filter out obvious false positives (like dataclass definitions)
                actual_hooks = [h for h in mapper.config_hooks if h['context'] != "module"]
                if actual_hooks:
                    report["ghost_hooks"].append({
                        "path": rel_path,
                        "hooks": actual_hooks
                    })
            
            # Potential targets: High priority folders with NO accel calls
            is_priority = any(p in rel_path for p in high_priority_patterns)
            if is_priority and not mapper.accel_calls:
                report["untapped"].append(rel_path)
                
        except Exception:
            pass

    # --- PROPAGATION TRACING ---
    print(f"\n[~] PROPAGATION TRACE (Where config flags flow)")
    print("-" * 60)

    for entry in sorted(report["ghost_hooks"] + report["reached"], key=lambda x: x["path"]):
        path = entry["path"]
        is_reached = any(r["path"] == path for r in report["reached"])
        status = "[FLOW]" if is_reached else "[SINK HOLE]"

        if entry.get("hooks"):
            unique_flags = set(h["flag"] for h in entry["hooks"])
            print(f"  {status} {path} receives {', '.join(unique_flags)}")


    print(f"\n[?] UNTAPPED (High Boolean Complexity, 0% Accel)")
    print("-" * 60)
    for path in sorted(report["untapped"]):
        print(f"  [??] {path}")

    # Summary Stats
    total_files = len(report["reached"]) + len(report["ghost_hooks"]) + len(report["untapped"])
    coverage = (len(report["reached"]) / total_files * 100) if total_files > 0 else 0
    print(f"\nSUMMARY:")
    print(f"  Accel Integration Coverage: {coverage:.1f}%")
    print(f"  Identified Bottlenecks:    {len(report['untapped'])}")
    print(f"  Logic Redundancies:        {len(report['ghost_hooks'])}")
    print("=" * 60)

if __name__ == "__main__":
    # Go up one level from scripts/
    project_root = Path(__file__).parent.parent
    analyze_project(str(project_root))
