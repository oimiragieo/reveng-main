# Plugins - Visualization

## Overview

Visualization plugins provide graphical representations of binary analysis results including control flow graphs, call graphs, data flow diagrams, and interactive visualizations.

**Location:** `/home/user/reveng-main/src/reveng/plugins/visualization/`

## Files in This Directory

### `function_graph_plugin.py` (12221 lines)
Function control flow graph visualization plugin.

**FunctionGraphPlugin:**
- **Category:** VISUALIZATION
- **Priority:** MEDIUM
- **Dependencies:** `graphviz`, `networkx`, `matplotlib`

**Features:**
1. **Control Flow Graphs (CFG)** - Basic block level flow visualization
2. **Call Graphs** - Function call relationships
3. **Data Flow Graphs** - Variable usage and propagation
4. **Dominator Trees** - Control flow dominance visualization
5. **Interactive Graphs** - Zoomable, clickable visualizations
6. **Export Formats** - PNG, SVG, PDF, HTML

**Graph Types:**
- **CFG** - Control flow within functions
- **Call Graph** - Inter-function calls
- **Data Flow** - Variable dependencies
- **Memory Layout** - Stack and heap visualization

**Usage:**
```python
from reveng.plugins.visualization import FunctionGraphPlugin

plugin = FunctionGraphPlugin()
result = plugin.visualize(context)

# Generates interactive HTML visualization
# Saves to context.output_dir/function_graphs/
```

## Architecture

### Visualization Pipeline

```
Binary Analysis Data
  ↓
Graph Construction
  ├─> Extract basic blocks
  ├─> Build edges (jumps, calls)
  └─> Add metadata
  ↓
Layout Algorithm
  ├─> Hierarchical layout
  ├─> Force-directed layout
  └─> Custom positioning
  ↓
Rendering
  ├─> SVG/PNG (static)
  ├─> HTML (interactive)
  └─> JSON (data export)
  ↓
Output Files
```

### Graph Types

```
FunctionGraphPlugin
  ├─> CFG Generator
  │   ├─> Basic block extraction
  │   ├─> Edge detection
  │   └─> Loop identification
  │
  ├─> Call Graph Generator
  │   ├─> Function discovery
  │   ├─> Call extraction
  │   └─> Cross-reference analysis
  │
  └─> Data Flow Generator
      ├─> Variable tracking
      ├─> Def-use chains
      └─> Dependency analysis
```

## Key Concepts

### 1. Graph Layouts

Different algorithms for different graph types:

**Hierarchical:**
- Best for control flow graphs
- Top-to-bottom flow
- Clear structure

**Force-Directed:**
- Best for call graphs
- Natural clustering
- Reveals patterns

**Custom:**
- Domain-specific layouts
- Optimized for readability

### 2. Interactive Features

HTML visualizations include:

- **Zoom/Pan** - Navigate large graphs
- **Node Click** - View details
- **Highlight Paths** - Trace execution
- **Search** - Find specific nodes
- **Filter** - Hide/show node types

### 3. Metadata Annotations

Nodes and edges include rich metadata:

```python
node = {
    "id": "0x401000",
    "label": "main",
    "type": "function",
    "size": 150,
    "instructions": 42,
    "complexity": "medium"
}

edge = {
    "from": "0x401000",
    "to": "0x401050",
    "type": "call",
    "conditional": False
}
```

## Usage Examples

### Example 1: Generate CFG for Function

```python
from reveng.plugins.visualization import FunctionGraphPlugin
from reveng.plugins.base import PluginContext

plugin = FunctionGraphPlugin()
context = PluginContext(
    binary_path="app.exe",
    options={
        "function_address": "0x401000",
        "graph_type": "cfg"
    }
)

result = plugin.visualize(context)

print(f"Graph saved to: {result['output_file']}")
print(f"Nodes: {result['node_count']}")
print(f"Edges: {result['edge_count']}")
```

### Example 2: Generate Full Call Graph

```python
context.options = {
    "graph_type": "call_graph",
    "include_imports": True,
    "max_depth": 5
}

result = plugin.visualize(context)

# Interactive HTML visualization
print(f"Open: {result['output_file']}")
```

### Example 3: Data Flow Visualization

```python
context.options = {
    "graph_type": "data_flow",
    "variable": "user_input",
    "show_taint_propagation": True
}

result = plugin.visualize(context)

# Traces how 'user_input' flows through the program
```

### Example 4: Export Multiple Formats

```python
context.options = {
    "graph_type": "cfg",
    "function_address": "0x401000",
    "output_formats": ["svg", "png", "html", "json"]
}

result = plugin.visualize(context)

for format_type, file_path in result['outputs'].items():
    print(f"{format_type}: {file_path}")
```

## Configuration

### Visualization Options

```python
context.options = {
    # Graph type
    "graph_type": "cfg",  # cfg, call_graph, data_flow

    # Layout
    "layout": "hierarchical",  # hierarchical, force, circular

    # Appearance
    "color_scheme": "dark",  # dark, light, colorblind
    "node_size": "proportional",  # fixed, proportional
    "show_instructions": True,
    "show_addresses": True,

    # Output
    "output_format": "html",  # html, svg, png, pdf, json
    "interactive": True,
    "resolution": "1920x1080"
}
```

### Theme Customization

```python
context.options["theme"] = {
    "background": "#1e1e1e",
    "node_colors": {
        "entry": "#4caf50",
        "exit": "#f44336",
        "conditional": "#ff9800",
        "call": "#2196f3"
    },
    "edge_colors": {
        "true_branch": "#4caf50",
        "false_branch": "#f44336",
        "call": "#2196f3"
    }
}
```

## Testing

### Unit Tests

```python
import pytest
from reveng.plugins.visualization import FunctionGraphPlugin

def test_cfg_generation():
    plugin = FunctionGraphPlugin()
    context = PluginContext(
        binary_path="test.exe",
        options={"graph_type": "cfg"}
    )

    result = plugin.visualize(context)

    assert result['node_count'] > 0
    assert result['edge_count'] > 0
    assert 'output_file' in result
    assert Path(result['output_file']).exists()
```

### Visual Regression Tests

```bash
# Compare generated visualizations
pytest tests/plugins/visualization/ --visual-regression
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/plugins/` - Plugin framework
- `/home/user/reveng-main/src/reveng/analyzers/` - Analysis data source

### External Dependencies
- `graphviz` - Graph rendering
- `networkx` - Graph algorithms
- `matplotlib` - Plotting
- `plotly` - Interactive visualizations (optional)

## Notes

**Best Practices:**
1. Use appropriate layout for graph type
2. Limit node count for readability (< 100 nodes ideal)
3. Use interactive mode for large graphs
4. Export to multiple formats for flexibility
5. Apply filters to reduce complexity

**Performance Considerations:**
- Large graphs (>1000 nodes) may be slow to render
- Interactive HTML works best for medium graphs
- Use SVG for print quality
- Use PNG for quick previews

**Future Enhancements:**
- [ ] 3D graph visualization
- [ ] Real-time execution tracing overlay
- [ ] Diff visualization (compare binaries)
- [ ] Integration with IDA/Ghidra
- [ ] WebGL-based rendering for large graphs
- [ ] VR/AR visualization (experimental)

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
