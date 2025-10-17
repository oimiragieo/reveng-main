"""
Function Graph Visualization Plugin for REVENG

Plugin for creating function call graphs and control flow visualizations.
"""

import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..base import VisualizationPlugin, PluginMetadata, PluginContext, PluginCategory, PluginPriority
from ...core.errors import PluginError
from ...core.logger import get_logger

logger = get_logger()

class FunctionGraphPlugin(VisualizationPlugin):
    """Function call graph visualization plugin"""

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return PluginMetadata(
            name="function_graph",
            version="1.0.0",
            description="Creates function call graphs and control flow visualizations",
            author="REVENG Team",
            category=PluginCategory.VISUALIZATION,
            priority=PluginPriority.NORMAL,
            dependencies=[],
            requirements=["graphviz", "networkx"],
            tags=["visualization", "graph", "function", "call", "flow"],
            homepage="https://github.com/reveng/reveng",
            license="MIT",
            min_reveng_version="1.0.0"
        )

    def initialize(self, context: PluginContext) -> bool:
        """Initialize the plugin"""
        try:
            # Check if required libraries are available
            try:
                import graphviz
                import networkx as nx
                self.graphviz = graphviz
                self.networkx = nx
            except ImportError as e:
                logger.error(f"Required libraries not available: {e}")
                return False

            logger.info("Function Graph plugin initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize Function Graph plugin: {e}")
            return False

    def visualize(self, context: PluginContext, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create function call graph visualization"""

        try:
            output_dir = Path(context.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Extract function data from analysis results
            functions = self._extract_functions(data)
            if not functions:
                logger.warning("No function data found for visualization")
                return {
                    "visualization_type": "function_graph",
                    "success": False,
                    "error": "No function data found"
                }

            # Create function call graph
            graph = self._create_function_graph(functions)

            # Generate different visualization formats
            results = {}

            # DOT format
            dot_file = output_dir / "function_graph.dot"
            self._save_dot_format(graph, dot_file)
            results["dot_file"] = str(dot_file)

            # PNG format
            png_file = output_dir / "function_graph.png"
            self._save_png_format(graph, png_file)
            results["png_file"] = str(png_file)

            # SVG format
            svg_file = output_dir / "function_graph.svg"
            self._save_svg_format(graph, svg_file)
            results["svg_file"] = str(svg_file)

            # JSON format
            json_file = output_dir / "function_graph.json"
            self._save_json_format(graph, json_file)
            results["json_file"] = str(json_file)

            # Graph statistics
            stats = self._calculate_graph_statistics(graph)
            results["statistics"] = stats

            logger.info(f"Function graph visualization completed: {len(functions)} functions")

            return {
                "visualization_type": "function_graph",
                "success": True,
                "output_files": results,
                "statistics": stats
            }

        except Exception as e:
            logger.error(f"Function graph visualization failed: {e}")
            return {
                "visualization_type": "function_graph",
                "success": False,
                "error": str(e)
            }

    def _extract_functions(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function information from analysis data"""

        functions = []

        # Look for function data in various analysis results
        for key, value in data.items():
            if isinstance(value, dict):
                # PE analysis results
                if "pe_info" in value and "functions" in value["pe_info"]:
                    functions.extend(value["pe_info"]["functions"])

                # Ghidra analysis results
                if "function_analysis" in value:
                    functions.extend(value["function_analysis"])

                # Direct function data
                if key == "functions" and isinstance(value, list):
                    functions.extend(value)

        return functions

    def _create_function_graph(self, functions: List[Dict[str, Any]]) -> 'networkx.DiGraph':
        """Create function call graph"""

        graph = self.networkx.DiGraph()

        # Add nodes (functions)
        for func in functions:
            func_name = func.get("name", f"func_{func.get('address', 'unknown')}")
            func_address = func.get("address", "unknown")
            func_size = func.get("size", 0)

            graph.add_node(
                func_name,
                address=func_address,
                size=func_size,
                calls=func.get("calls", []),
                callers=func.get("callers", [])
            )

        # Add edges (function calls)
        for func in functions:
            func_name = func.get("name", f"func_{func.get('address', 'unknown')}")
            calls = func.get("calls", [])

            for call in calls:
                if isinstance(call, str):
                    called_func = call
                elif isinstance(call, dict):
                    called_func = call.get("name", call.get("address", "unknown"))
                else:
                    continue

                if called_func in graph.nodes:
                    graph.add_edge(func_name, called_func)

        return graph

    def _save_dot_format(self, graph: 'networkx.DiGraph', output_file: Path):
        """Save graph in DOT format"""

        try:
            dot_content = self.networkx.nx_pydot.to_pydot(graph).to_string()
            with open(output_file, 'w') as f:
                f.write(dot_content)
            logger.info(f"DOT format saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save DOT format: {e}")

    def _save_png_format(self, graph: 'networkx.DiGraph', output_file: Path):
        """Save graph as PNG image"""

        try:
            # Create Graphviz object
            dot = self.graphviz.Digraph(comment='Function Call Graph')
            dot.attr(rankdir='TB', size='12,8')
            dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')
            dot.attr('edge', color='gray')

            # Add nodes
            for node in graph.nodes():
                node_data = graph.nodes[node]
                label = f"{node}\\n{node_data.get('address', '')}\\nSize: {node_data.get('size', 0)}"
                dot.node(node, label)

            # Add edges
            for edge in graph.edges():
                dot.edge(edge[0], edge[1])

            # Render PNG
            dot.render(str(output_file.with_suffix('')), format='png', cleanup=True)
            logger.info(f"PNG format saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save PNG format: {e}")

    def _save_svg_format(self, graph: 'networkx.DiGraph', output_file: Path):
        """Save graph as SVG image"""

        try:
            # Create Graphviz object
            dot = self.graphviz.Digraph(comment='Function Call Graph')
            dot.attr(rankdir='TB', size='12,8')
            dot.attr('node', shape='box', style='rounded,filled', fillcolor='lightblue')
            dot.attr('edge', color='gray')

            # Add nodes
            for node in graph.nodes():
                node_data = graph.nodes[node]
                label = f"{node}\\n{node_data.get('address', '')}\\nSize: {node_data.get('size', 0)}"
                dot.node(node, label)

            # Add edges
            for edge in graph.edges():
                dot.edge(edge[0], edge[1])

            # Render SVG
            dot.render(str(output_file.with_suffix('')), format='svg', cleanup=True)
            logger.info(f"SVG format saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save SVG format: {e}")

    def _save_json_format(self, graph: 'networkx.DiGraph', output_file: Path):
        """Save graph in JSON format"""

        try:
            # Convert to JSON-serializable format
            graph_data = {
                "nodes": [
                    {
                        "id": node,
                        "address": graph.nodes[node].get("address", ""),
                        "size": graph.nodes[node].get("size", 0),
                        "calls": graph.nodes[node].get("calls", []),
                        "callers": graph.nodes[node].get("callers", [])
                    }
                    for node in graph.nodes()
                ],
                "edges": [
                    {
                        "source": edge[0],
                        "target": edge[1]
                    }
                    for edge in graph.edges()
                ]
            }

            with open(output_file, 'w') as f:
                json.dump(graph_data, f, indent=2)
            logger.info(f"JSON format saved to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to save JSON format: {e}")

    def _calculate_graph_statistics(self, graph: 'networkx.DiGraph') -> Dict[str, Any]:
        """Calculate graph statistics"""

        try:
            stats = {
                "total_nodes": graph.number_of_nodes(),
                "total_edges": graph.number_of_edges(),
                "density": self.networkx.density(graph),
                "is_connected": self.networkx.is_weakly_connected(graph),
                "number_of_components": self.networkx.number_weakly_connected_components(graph),
                "average_degree": sum(dict(graph.degree()).values()) / graph.number_of_nodes() if graph.number_of_nodes() > 0 else 0,
                "max_degree": max(dict(graph.degree()).values()) if graph.number_of_nodes() > 0 else 0,
                "min_degree": min(dict(graph.degree()).values()) if graph.number_of_nodes() > 0 else 0
            }

            # Calculate centrality measures
            if graph.number_of_nodes() > 0:
                try:
                    stats["betweenness_centrality"] = self.networkx.betweenness_centrality(graph)
                    stats["closeness_centrality"] = self.networkx.closeness_centrality(graph)
                    stats["eigenvector_centrality"] = self.networkx.eigenvector_centrality(graph)
                except Exception as e:
                    logger.warning(f"Failed to calculate centrality measures: {e}")

            return stats

        except Exception as e:
            logger.error(f"Failed to calculate graph statistics: {e}")
            return {}

    def cleanup(self, context: PluginContext) -> bool:
        """Cleanup plugin resources"""
        try:
            logger.info("Function Graph plugin cleanup completed")
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup Function Graph plugin: {e}")
            return False
