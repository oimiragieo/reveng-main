# Directory: src/reveng/plugins

## Overview
This directory implements a plugin system for extending REVENG functionality. It provides a base plugin architecture and includes built-in plugins for analysis, security, AI, and visualization.

## Files in This Directory

### base.py
- **Purpose**: Base plugin class and plugin interface
- **Key Classes**: `BasePlugin`, `PluginMetadata`
- **Key Functions**: Plugin lifecycle methods (initialize, execute, cleanup)

### manager.py
- **Purpose**: Plugin manager for loading, registering, and executing plugins
- **Key Classes**: `PluginManager`
- **Key Functions**:
  - `load_plugin()`: Load plugin from file
  - `register_plugin()`: Register plugin instance
  - `execute_plugin()`: Execute plugin
  - `list_plugins()`: List available plugins

## Subdirectories

### analysis/
Analysis plugins:
- `pe_analyzer_plugin.py`: PE binary analysis plugin

### security/
Security plugins:
- `malware_detection_plugin.py`: Malware detection plugin

### ai/
AI plugins:
- `code_reconstruction_plugin.py`: AI code reconstruction plugin

### visualization/
Visualization plugins:
- `function_graph_plugin.py`: Function call graph visualization

## Architecture

```
┌─────────────────────────────────────┐
│   Plugin Manager                    │
├─────────────────────────────────────┤
│ • Plugin discovery                  │
│ • Plugin loading                    │
│ • Plugin execution                  │
│ • Event coordination                │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────┐
       │   Plugin Categories    │
       ├────────────────────────┤
       │ • Analysis             │
       │ • Security             │
       │ • AI                   │
       │ • Visualization        │
       └────────────────────────┘
```

## Key Concepts

### Plugin Lifecycle
1. **Discovery**: Find available plugins
2. **Load**: Import plugin module
3. **Initialize**: Call plugin.initialize()
4. **Execute**: Run plugin.execute()
5. **Cleanup**: Call plugin.cleanup()

### Plugin Types
- **Analysis**: Extend binary analysis capabilities
- **Security**: Add security checks
- **AI**: AI-powered features
- **Visualization**: Visual representations

## Usage Examples

### Creating a Plugin
```python
from reveng.plugins.base import BasePlugin, PluginMetadata

class MyPlugin(BasePlugin):
    def __init__(self):
        super().__init__(
            metadata=PluginMetadata(
                name="my_plugin",
                version="1.0.0",
                description="My custom plugin",
                author="Me"
            )
        )

    def initialize(self, config):
        # Setup plugin
        pass

    def execute(self, context):
        # Main plugin logic
        return {"result": "success"}

    def cleanup(self):
        # Cleanup resources
        pass
```

### Using Plugin Manager
```python
from reveng.plugins.manager import PluginManager

manager = PluginManager()

# Load plugins
manager.load_plugin("/path/to/plugin.py")

# Execute plugin
result = manager.execute_plugin("my_plugin", context)
```

## Related Modules

### Used By
- `src/reveng/analyzer.py`: Can use plugins for extensibility
- Custom integrations

## Notes

### Plugin Development
1. Inherit from BasePlugin
2. Implement required methods
3. Provide metadata
4. Handle errors gracefully
5. Clean up resources
