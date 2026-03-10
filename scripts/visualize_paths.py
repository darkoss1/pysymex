import json
import os
import sys

# Setup path imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pysymex.core.state import VMState
from pysymex.execution.executor import SymbolicExecutor


class PathTracer:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.current_step = 0

    def init_path(self, path_id):
        if path_id not in self.nodes:
            self.nodes[path_id] = {"id": path_id, "events": [], "status": "running"}

    def record_event(self, path_id, pc, opname, constraints):
        self.init_path(path_id)
        self.nodes[path_id]["events"].append(
            {"step": self.current_step, "pc": pc, "opname": opname, "constraints": constraints}
        )
        self.current_step += 1

    def record_fork(self, parent_id, child_id):
        self.init_path(parent_id)
        self.init_path(child_id)
        self.edges.append({"source": parent_id, "target": child_id})

    def export(self, filepath):
        with open(filepath, "w") as f:
            json.dump({"nodes": list(self.nodes.values()), "edges": self.edges}, f, indent=2)


tracer = PathTracer()

# Monkey patch VMState.fork
original_fork = VMState.fork


def hooked_fork(self):
    new_state = original_fork(self)
    tracer.record_fork(self.path_id, new_state.path_id)
    return new_state


VMState.fork = hooked_fork

# Monkey patch SymbolicExecutor._execute_step
original_execute_step = SymbolicExecutor._execute_step


def hooked_execute_step(self, state):
    instr = None
    if state.pc < len(self._instructions):
        instr = self._instructions[state.pc]

    opname = getattr(instr, "opname", "UNKNOWN") if instr else "EOF"
    tracer.record_event(state.path_id, state.pc, opname, len(state.path_constraints))

    return original_execute_step(self, state)


SymbolicExecutor._execute_step = hooked_execute_step


def generate_html(json_path, html_path):
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>pysymex Path Visualizer</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #1e1e1e; color: #fff; margin: 0; padding: 20px; }}
        .node circle {{ fill: #4a90e2; stroke: #fff; stroke-width: 2px; }}
        .node text {{ font: 12px sans-serif; fill: #fff; }}
        .link {{ fill: none; stroke: #555; stroke-width: 2px; }}
        #info {{ position: absolute; top: 20px; right: 20px; width: 300px; background: #2d2d2d; padding: 15px; border-radius: 8px; border: 1px solid #444; }}
        h1 {{ color: #4a90e2; }}
    </style>
</head>
<body>
    <h1>pysymex Path Execution Tree</h1>
    <div id="graph"></div>
    <div id="info">
        <h3>Path Details</h3>
        <p id="details">Hover over a node to see execution events.</p>
    </div>
    <script>
        fetch('{json_path}')
            .then(r => r.json())
            .then(data => {{
                // Convert list of edges to a nested hierarchical tree for D3
                const rootId = data.nodes[0] ? data.nodes[0].id : 0;
                
                const stratify = d3.stratify()
                    .id(d => d.id)
                    .parentId(d => {{
                        const edge = data.edges.find(e => e.target === d.id);
                        return edge ? edge.source : null;
                    }});
                
                const root = stratify(data.nodes);
                
                const width = window.innerWidth - 350;
                const height = window.innerHeight - 100;
                
                const svg = d3.select("#graph").append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .append("g")
                    .attr("transform", "translate(40,40)");
                    
                const tree = d3.tree().size([width - 100, height - 100]);
                tree(root);
                
                svg.selectAll(".link")
                    .data(root.links())
                    .enter().append("path")
                    .attr("class", "link")
                    .attr("d", d3.linkVertical()
                        .x(d => d.x)
                        .y(d => d.y));
                        
                const node = svg.selectAll(".node")
                    .data(root.descendants())
                    .enter().append("g")
                    .attr("class", "node")
                    .attr("transform", d => `translate(${{d.x}},${{d.y}})`)
                    .on("mouseover", function(event, d) {{
                        const evs = d.data.events;
                        const summary = evs.slice(-10).map(e => `PC ${{e.pc}}: ${{e.opname}} (Constraints: ${{e.constraints}})`).join("<br>");
                        d3.select("#details").html(`<b>Path ID:</b> ${{d.data.id}}<br><b>Total Steps:</b> ${{evs.length}}<br><br><b>Last 10 Events:</b><br>${{summary}}`);
                        d3.select(this).select("circle").style("fill", "#e74c3c");
                    }})
                    .on("mouseout", function(event, d) {{
                        d3.select(this).select("circle").style("fill", "#4a90e2");
                    }});
                    
                node.append("circle").attr("r", 10);
                node.append("text")
                    .attr("dy", ".35em")
                    .attr("x", 15)
                    .text(d => `Path ${{d.data.id}}`);
            }});
    </script>
</body>
</html>
"""
    with open(html_path, "w") as f:
        f.write(html)
    print(f"\\n[+] Visualizer generated at: {html_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/visualize_paths.py <python_file_to_scan>")
        sys.exit(1)

    target_file = sys.argv[1]
    print(f"[*] Tracing execution of {target_file}...")

    # Hook into CLI to spin up full core engine
    from pysymex.cli import main

    sys.argv = ["pysymex", "scan", "--mode", "symbolic", target_file]
    try:
        main()
    except SystemExit:
        pass

    # Export Trace
    tracer.export("path_tree.json")
    generate_html("path_tree.json", "visualize.html")

    print("[*] Tracing complete!")
