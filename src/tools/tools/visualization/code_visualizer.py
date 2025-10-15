#!/usr/bin/env python3
"""
REVENG Code Visualizer
======================

Generates interactive visualizations for reverse-engineered code:
- Call graphs (function call relationships)
- Dependency diagrams (module/class dependencies)
- Control flow graphs (CFG)
- Data flow diagrams
- Class hierarchy diagrams

Output formats:
- Interactive HTML (vis.js, D3.js)
- Static images (Graphviz DOT)
- JSON (for custom rendering)

Requires:
- networkx - Graph algorithms
- graphviz - DOT rendering
- Optional: pydot, matplotlib
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    logger.warning("networkx not available - install with: pip install networkx")
    NETWORKX_AVAILABLE = False

try:
    import graphviz
    GRAPHVIZ_AVAILABLE = True
except ImportError:
    logger.warning("graphviz not available - install with: pip install graphviz")
    GRAPHVIZ_AVAILABLE = False


@dataclass
class CallGraphNode:
    """Node in call graph (function/method)"""
    name: str
    full_name: str
    file: str
    line: int
    calls: List[str]  # Functions called by this function
    called_by: List[str]  # Functions that call this function
    node_type: str  # 'function', 'method', 'constructor', etc.


@dataclass
class DependencyNode:
    """Node in dependency graph (module/class)"""
    name: str
    type: str  # 'module', 'class', 'package'
    file: str
    dependencies: List[str]  # What this depends on
    dependents: List[str]  # What depends on this


class CallGraphBuilder:
    """
    Builds call graphs from source code analysis

    Supports:
    - Java (from decompiled source)
    - C/C++ (from Ghidra analysis)
    - Python (from AST analysis)
    - C# (from IL analysis)
    """

    def __init__(self):
        self.nodes: Dict[str, CallGraphNode] = {}
        self.edges: List[Tuple[str, str]] = []

    def build_from_java_analysis(self, analysis_dir: str) -> nx.DiGraph:
        """Build call graph from Java bytecode analysis results"""
        if not NETWORKX_AVAILABLE:
            raise RuntimeError("networkx is required for call graph generation")

        analysis_path = Path(analysis_dir)

        # Read decompiled Java files
        decompiled_dir = analysis_path / 'decompiled'
        if decompiled_dir.exists():
            for java_file in decompiled_dir.rglob('*.java'):
                self._parse_java_file(java_file)

        return self._build_graph()

    def build_from_ghidra_analysis(self, analysis_dir: str) -> nx.DiGraph:
        """Build call graph from Ghidra analysis results"""
        if not NETWORKX_AVAILABLE:
            raise RuntimeError("networkx is required for call graph generation")

        analysis_path = Path(analysis_dir)

        # Read functions.json (contains call graph data)
        functions_file = analysis_path / 'functions.json'
        if functions_file.exists():
            with open(functions_file, 'r') as f:
                functions = json.load(f)

            for func in functions:
                self._add_function_from_ghidra(func)

        # Read call_graphs directory
        call_graphs_dir = analysis_path / 'call_graphs'
        if call_graphs_dir.exists():
            for cg_file in call_graphs_dir.glob('*.json'):
                with open(cg_file, 'r') as f:
                    cg_data = json.load(f)
                    self._process_ghidra_call_graph(cg_data)

        return self._build_graph()

    def _parse_java_file(self, java_file: Path):
        """Parse Java file to extract function calls"""
        try:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Failed to read {java_file}: {e}")
            return

        # Extract package
        package_match = re.search(r'package\s+([\w.]+);', content)
        package = package_match.group(1) if package_match else ''

        # Extract class name
        class_match = re.search(r'class\s+(\w+)', content)
        if not class_match:
            return
        class_name = class_match.group(1)

        # Extract methods
        method_pattern = r'(?:public|private|protected)?\s+(?:static\s+)?(?:[\w<>]+)\s+(\w+)\s*\(([^)]*)\)\s*\{'
        for match in re.finditer(method_pattern, content):
            method_name = match.group(1)
            full_name = f"{package}.{class_name}.{method_name}" if package else f"{class_name}.{method_name}"

            # Extract method body to find calls
            start = match.end()
            # Find matching closing brace (simplified - doesn't handle nested braces perfectly)
            brace_count = 1
            end = start
            while end < len(content) and brace_count > 0:
                if content[end] == '{':
                    brace_count += 1
                elif content[end] == '}':
                    brace_count -= 1
                end += 1

            method_body = content[start:end]

            # Find function calls in body
            calls = self._extract_calls_from_java(method_body)

            # Create node
            line_num = content[:match.start()].count('\n') + 1
            node = CallGraphNode(
                name=method_name,
                full_name=full_name,
                file=str(java_file),
                line=line_num,
                calls=calls,
                called_by=[],
                node_type='method'
            )

            self.nodes[full_name] = node

            # Add edges
            for call in calls:
                self.edges.append((full_name, call))

    def _extract_calls_from_java(self, method_body: str) -> List[str]:
        """Extract function calls from Java method body"""
        calls = []

        # Pattern: functionName(...) or object.methodName(...)
        call_pattern = r'(?:[\w.]+\.)?(\w+)\s*\('

        for match in re.finditer(call_pattern, method_body):
            func_name = match.group(1)
            # Skip Java keywords
            if func_name not in ['if', 'while', 'for', 'switch', 'catch', 'synchronized']:
                calls.append(func_name)

        return list(set(calls))  # Remove duplicates

    def _add_function_from_ghidra(self, func_data: Dict):
        """Add function from Ghidra analysis"""
        name = func_data.get('name', 'unknown')
        address = func_data.get('address', '0x0')
        full_name = f"{name}@{address}"

        # Extract calls (callees)
        calls = func_data.get('callees', [])
        called_by = func_data.get('callers', [])

        node = CallGraphNode(
            name=name,
            full_name=full_name,
            file='',
            line=0,
            calls=calls,
            called_by=called_by,
            node_type='function'
        )

        self.nodes[full_name] = node

        # Add edges
        for callee in calls:
            self.edges.append((full_name, callee))

    def _process_ghidra_call_graph(self, cg_data: Dict):
        """Process Ghidra call graph data"""
        # Add nodes and edges from call graph
        for node_name, node_data in cg_data.items():
            if node_name not in self.nodes:
                self.nodes[node_name] = CallGraphNode(
                    name=node_name,
                    full_name=node_name,
                    file='',
                    line=0,
                    calls=[],
                    called_by=[],
                    node_type='function'
                )

    def _build_graph(self) -> nx.DiGraph:
        """Build NetworkX directed graph from nodes and edges"""
        G = nx.DiGraph()

        # Add nodes
        for node_name, node_data in self.nodes.items():
            G.add_node(node_name, **asdict(node_data))

        # Add edges
        for source, target in self.edges:
            # Only add edge if target node exists
            if target in self.nodes or any(target in n for n in self.nodes):
                # Try exact match first
                if target in self.nodes:
                    G.add_edge(source, target)
                else:
                    # Try partial match (method name only)
                    for full_target in self.nodes:
                        if full_target.endswith('.' + target):
                            G.add_edge(source, full_target)
                            break

        return G


class DependencyGraphBuilder:
    """
    Builds dependency graphs from code analysis

    Shows:
    - Module dependencies (imports)
    - Class dependencies (inheritance, composition)
    - Package dependencies
    """

    def __init__(self):
        self.nodes: Dict[str, DependencyNode] = {}
        self.edges: List[Tuple[str, str]] = []

    def build_from_java_analysis(self, analysis_dir: str) -> nx.DiGraph:
        """Build dependency graph from Java analysis"""
        if not NETWORKX_AVAILABLE:
            raise RuntimeError("networkx is required for dependency graph generation")

        analysis_path = Path(analysis_dir)

        # Read decompiled Java files
        decompiled_dir = analysis_path / 'decompiled'
        if decompiled_dir.exists():
            for java_file in decompiled_dir.rglob('*.java'):
                self._parse_java_dependencies(java_file)

        return self._build_graph()

    def _parse_java_dependencies(self, java_file: Path):
        """Parse Java file to extract dependencies"""
        try:
            content = java_file.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return

        # Extract package
        package_match = re.search(r'package\s+([\w.]+);', content)
        package = package_match.group(1) if package_match else ''

        # Extract class name
        class_match = re.search(r'class\s+(\w+)', content)
        if not class_match:
            return
        class_name = class_match.group(1)
        full_name = f"{package}.{class_name}" if package else class_name

        # Extract imports
        imports = re.findall(r'import\s+([\w.]+);', content)

        # Extract extends/implements
        extends_match = re.search(r'extends\s+([\w.]+)', content)
        implements_match = re.search(r'implements\s+([\w.,\s]+)', content)

        dependencies = imports.copy()
        if extends_match:
            dependencies.append(extends_match.group(1))
        if implements_match:
            interfaces = [i.strip() for i in implements_match.group(1).split(',')]
            dependencies.extend(interfaces)

        # Create node
        node = DependencyNode(
            name=class_name,
            type='class',
            file=str(java_file),
            dependencies=dependencies,
            dependents=[]
        )

        self.nodes[full_name] = node

        # Add edges
        for dep in dependencies:
            self.edges.append((full_name, dep))

    def _build_graph(self) -> nx.DiGraph:
        """Build NetworkX directed graph"""
        G = nx.DiGraph()

        # Add nodes
        for node_name, node_data in self.nodes.items():
            G.add_node(node_name, **asdict(node_data))

        # Add edges
        for source, target in self.edges:
            G.add_edge(source, target)

        return G


class GraphVisualizer:
    """
    Generates visualizations from NetworkX graphs

    Output formats:
    1. Interactive HTML (vis.js)
    2. Static DOT/PNG (Graphviz)
    3. JSON (for custom rendering)
    """

    def __init__(self, output_dir: str = "visualizations"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def render_call_graph(self, graph: nx.DiGraph, output_name: str = "call_graph"):
        """Render call graph in multiple formats"""
        logger.info(f"Rendering call graph with {len(graph.nodes)} nodes and {len(graph.edges)} edges")

        # 1. Generate interactive HTML
        self._generate_html_vis(graph, output_name, "Call Graph")

        # 2. Generate Graphviz DOT
        if GRAPHVIZ_AVAILABLE:
            self._generate_graphviz(graph, output_name)

        # 3. Generate JSON
        self._generate_json(graph, output_name)

        # 4. Generate statistics
        self._generate_statistics(graph, output_name)

    def _generate_html_vis(self, graph: nx.DiGraph, name: str, title: str):
        """Generate interactive HTML visualization using vis.js"""
        # Convert NetworkX graph to vis.js format
        nodes_data = []
        for node_id in graph.nodes():
            node_attrs = graph.nodes[node_id]
            nodes_data.append({
                'id': node_id,
                'label': node_attrs.get('name', node_id),
                'title': f"{node_id}\nFile: {node_attrs.get('file', 'unknown')}",
                'group': node_attrs.get('node_type', 'default')
            })

        edges_data = []
        for source, target in graph.edges():
            edges_data.append({
                'from': source,
                'to': target,
                'arrows': 'to'
            })

        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        #network {{
            width: 100%;
            height: 900px;
            border: 1px solid lightgray;
        }}
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
        }}
        h1 {{
            color: #333;
        }}
        .controls {{
            margin: 20px 0;
        }}
        button {{
            padding: 10px 20px;
            margin-right: 10px;
            cursor: pointer;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="controls">
        <button onclick="network.fit()">Fit to Screen</button>
        <button onclick="network.stabilize()">Stabilize</button>
        <button onclick="exportImage()">Export PNG</button>
    </div>
    <div id="network"></div>

    <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(nodes_data)});
        var edges = new vis.DataSet({json.dumps(edges_data)});

        var container = document.getElementById('network');
        var data = {{
            nodes: nodes,
            edges: edges
        }};
        var options = {{
            nodes: {{
                shape: 'box',
                font: {{
                    size: 14
                }},
                borderWidth: 2,
                shadow: true
            }},
            edges: {{
                width: 2,
                shadow: true,
                smooth: {{
                    type: 'cubicBezier',
                    forceDirection: 'horizontal',
                    roundness: 0.4
                }}
            }},
            layout: {{
                hierarchical: {{
                    direction: 'UD',
                    sortMethod: 'directed',
                    nodeSpacing: 150,
                    levelSeparation: 200
                }}
            }},
            physics: {{
                enabled: false
            }},
            interaction: {{
                navigationButtons: true,
                keyboard: true
            }}
        }};

        var network = new vis.Network(container, data, options);

        network.on("click", function(params) {{
            if (params.nodes.length > 0) {{
                var nodeId = params.nodes[0];
                var node = nodes.get(nodeId);
                console.log("Clicked node:", node);
            }}
        }});

        function exportImage() {{
            var canvas = document.querySelector('#network canvas');
            var link = document.createElement('a');
            link.download = '{name}.png';
            link.href = canvas.toDataURL();
            link.click();
        }}
    </script>
</body>
</html>'''

        output_file = self.output_dir / f"{name}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"Generated interactive HTML: {output_file}")

    def _generate_graphviz(self, graph: nx.DiGraph, name: str):
        """Generate Graphviz DOT file and render to PNG"""
        try:
            dot = graphviz.Digraph(comment='Call Graph', format='png')
            dot.attr(rankdir='TB', size='20,20')
            dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')

            # Add nodes
            for node_id in graph.nodes():
                node_attrs = graph.nodes[node_id]
                label = node_attrs.get('name', node_id)
                dot.node(node_id, label)

            # Add edges
            for source, target in graph.edges():
                dot.edge(source, target)

            # Save DOT file
            dot_file = self.output_dir / f"{name}.dot"
            with open(dot_file, 'w') as f:
                f.write(dot.source)

            # Render to PNG
            output_path = str(self.output_dir / name)
            dot.render(output_path, format='png', cleanup=True)

            logger.info(f"Generated Graphviz visualization: {output_path}.png")

        except Exception as e:
            logger.warning(f"Failed to generate Graphviz: {e}")

    def _generate_json(self, graph: nx.DiGraph, name: str):
        """Generate JSON representation of graph"""
        graph_data = {
            'nodes': [
                {
                    'id': node_id,
                    **graph.nodes[node_id]
                }
                for node_id in graph.nodes()
            ],
            'edges': [
                {
                    'source': source,
                    'target': target,
                    **graph.edges[source, target]
                }
                for source, target in graph.edges()
            ],
            'statistics': {
                'node_count': len(graph.nodes),
                'edge_count': len(graph.edges),
                'density': nx.density(graph),
            }
        }

        json_file = self.output_dir / f"{name}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Generated JSON: {json_file}")

    def _generate_statistics(self, graph: nx.DiGraph, name: str):
        """Generate graph statistics"""
        stats = {
            'nodes': len(graph.nodes),
            'edges': len(graph.edges),
            'density': nx.density(graph),
            'average_degree': sum(dict(graph.degree()).values()) / len(graph.nodes) if graph.nodes else 0,
        }

        # Find most connected nodes
        degree_dict = dict(graph.degree())
        sorted_nodes = sorted(degree_dict.items(), key=lambda x: x[1], reverse=True)
        stats['most_connected'] = sorted_nodes[:10]

        # Save statistics
        stats_file = self.output_dir / f"{name}_statistics.json"
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, indent=2)

        # Print statistics
        print("\n" + "="*60)
        print(f"GRAPH STATISTICS: {name}")
        print("="*60)
        print(f"Nodes: {stats['nodes']}")
        print(f"Edges: {stats['edges']}")
        print(f"Density: {stats['density']:.4f}")
        print(f"Average Degree: {stats['average_degree']:.2f}")
        print(f"\nMost Connected Nodes:")
        for node, degree in stats['most_connected'][:5]:
            print(f"  {node}: {degree} connections")
        print("="*60)


def main():
    """CLI interface for code visualization"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Generate call graphs and dependency diagrams from code analysis'
    )
    parser.add_argument('analysis_dir', help='Path to analysis output directory')
    parser.add_argument('--type', choices=['call-graph', 'dependency', 'both'],
                       default='both', help='Visualization type')
    parser.add_argument('--format', choices=['java', 'ghidra', 'auto'],
                       default='auto', help='Analysis format')
    parser.add_argument('-o', '--output', default='visualizations',
                       help='Output directory for visualizations')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if not NETWORKX_AVAILABLE:
        print("Error: networkx is required. Install with: pip install networkx")
        return 1

    # Build graphs
    call_graph_builder = CallGraphBuilder()
    dependency_builder = DependencyGraphBuilder()
    visualizer = GraphVisualizer(output_dir=args.output)

    # Auto-detect format
    analysis_path = Path(args.analysis_dir)
    if args.format == 'auto':
        if (analysis_path / 'decompiled').exists():
            args.format = 'java'
        elif (analysis_path / 'functions.json').exists():
            args.format = 'ghidra'
        else:
            print("Error: Could not auto-detect analysis format")
            return 1

    # Generate visualizations
    if args.type in ['call-graph', 'both']:
        if args.format == 'java':
            call_graph = call_graph_builder.build_from_java_analysis(args.analysis_dir)
        else:
            call_graph = call_graph_builder.build_from_ghidra_analysis(args.analysis_dir)

        visualizer.render_call_graph(call_graph, "call_graph")

    if args.type in ['dependency', 'both'] and args.format == 'java':
        dependency_graph = dependency_builder.build_from_java_analysis(args.analysis_dir)
        visualizer.render_call_graph(dependency_graph, "dependency_graph")

    print(f"\nVisualizations saved to: {args.output}")
    return 0


if __name__ == '__main__':
    exit(main())
