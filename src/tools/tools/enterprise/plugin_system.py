#!/usr/bin/env python3
"""
REVENG Plugin System
====================

Extensible plugin architecture for custom analyzers and processors.

Features:
- Plugin discovery and loading
- Plugin lifecycle management
- Plugin API with hooks
- Plugin configuration
- Plugin versioning and dependencies
- Plugin marketplace integration (future)

Plugin types:
- Analyzers: Custom analysis logic
- Decompilers: Additional decompiler backends
- Obfuscators/Deobfuscators: Custom patterns
- Exporters: Custom output formats
- Preprocessors: Input file transformations
- Postprocessors: Result transformations
"""

import os
import sys
import json
import logging
import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Type
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
from enum import Enum

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Types of plugins"""
    ANALYZER = "analyzer"
    DECOMPILER = "decompiler"
    DEOBFUSCATOR = "deobfuscator"
    EXPORTER = "exporter"
    PREPROCESSOR = "preprocessor"
    POSTPROCESSOR = "postprocessor"
    VISUALIZER = "visualizer"


class PluginHook(Enum):
    """Plugin execution hooks"""
    PRE_ANALYSIS = "pre_analysis"
    POST_ANALYSIS = "post_analysis"
    PRE_DECOMPILATION = "pre_decompilation"
    POST_DECOMPILATION = "post_decompilation"
    PRE_EXPORT = "pre_export"
    POST_EXPORT = "post_export"


@dataclass
class PluginMetadata:
    """Metadata for a plugin"""
    name: str
    version: str
    author: str
    description: str
    plugin_type: str
    entry_point: str  # Module.ClassName

    # Optional
    dependencies: List[str] = None
    config_schema: Dict[str, Any] = None
    hooks: List[str] = None
    supported_formats: List[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.config_schema is None:
            self.config_schema = {}
        if self.hooks is None:
            self.hooks = []
        if self.supported_formats is None:
            self.supported_formats = []


@dataclass
class PluginInfo:
    """Runtime plugin information"""
    metadata: PluginMetadata
    plugin_instance: Any
    enabled: bool
    loaded: bool
    error: Optional[str] = None


class PluginBase(ABC):
    """
    Base class for all plugins

    All plugins must inherit from this class and implement required methods
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize plugin

        Args:
            config: Plugin configuration dictionary
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.version = "1.0.0"

    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass

    @abstractmethod
    def execute(self, input_data: Any, context: Dict) -> Any:
        """
        Execute plugin logic

        Args:
            input_data: Input data to process
            context: Execution context (session info, etc.)

        Returns:
            Processed output data
        """
        pass

    def validate_config(self) -> bool:
        """Validate plugin configuration"""
        return True

    def on_load(self):
        """Called when plugin is loaded"""
        pass

    def on_unload(self):
        """Called when plugin is unloaded"""
        pass


class AnalyzerPlugin(PluginBase):
    """Base class for analyzer plugins"""

    @abstractmethod
    def analyze(self, file_path: str, context: Dict) -> Dict:
        """
        Analyze a file

        Args:
            file_path: Path to file to analyze
            context: Analysis context

        Returns:
            Analysis results dictionary
        """
        pass

    def execute(self, input_data: Any, context: Dict) -> Any:
        """Execute analyzer - calls analyze()"""
        return self.analyze(input_data, context)


class DecompilerPlugin(PluginBase):
    """Base class for decompiler plugins"""

    @abstractmethod
    def decompile(self, input_file: str, output_file: str, context: Dict) -> bool:
        """
        Decompile a file

        Args:
            input_file: Path to compiled file
            output_file: Path for decompiled output
            context: Decompilation context

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported file formats"""
        pass

    def execute(self, input_data: Any, context: Dict) -> Any:
        """Execute decompiler"""
        input_file = input_data.get('input_file')
        output_file = input_data.get('output_file')
        return self.decompile(input_file, output_file, context)


class ExporterPlugin(PluginBase):
    """Base class for exporter plugins"""

    @abstractmethod
    def export(self, data: Any, output_path: str, context: Dict) -> bool:
        """
        Export data to custom format

        Args:
            data: Data to export
            output_path: Output file path
            context: Export context

        Returns:
            True if successful
        """
        pass

    @abstractmethod
    def get_format_name(self) -> str:
        """Return export format name (e.g., 'PDF', 'XML', 'CSV')"""
        pass

    def execute(self, input_data: Any, context: Dict) -> Any:
        """Execute exporter"""
        data = input_data.get('data')
        output_path = input_data.get('output_path')
        return self.export(data, output_path, context)


class PluginManager:
    """
    Manages plugin discovery, loading, and execution

    Workflow:
    1. Discover plugins in plugins/ directory
    2. Load plugin metadata
    3. Validate dependencies
    4. Load plugin code
    5. Register hooks
    6. Execute plugins when triggered
    """

    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)

        self.plugins: Dict[str, PluginInfo] = {}
        self.hooks: Dict[str, List[str]] = {hook.value: [] for hook in PluginHook}

        # Create plugin subdirectories
        for plugin_type in PluginType:
            (self.plugins_dir / plugin_type.value).mkdir(exist_ok=True)

    def discover_plugins(self):
        """Discover all available plugins"""
        logger.info(f"Discovering plugins in {self.plugins_dir}")

        for plugin_type in PluginType:
            type_dir = self.plugins_dir / plugin_type.value

            # Find all plugin.json files
            for plugin_json in type_dir.rglob('plugin.json'):
                try:
                    self._load_plugin_metadata(plugin_json)
                except Exception as e:
                    logger.error(f"Failed to load plugin from {plugin_json}: {e}")

        logger.info(f"Discovered {len(self.plugins)} plugins")

    def _load_plugin_metadata(self, plugin_json_path: Path):
        """Load plugin metadata from plugin.json"""
        with open(plugin_json_path, 'r', encoding='utf-8') as f:
            metadata_dict = json.load(f)

        metadata = PluginMetadata(**metadata_dict)
        plugin_dir = plugin_json_path.parent

        # Create plugin info (not loaded yet)
        plugin_info = PluginInfo(
            metadata=metadata,
            plugin_instance=None,
            enabled=False,
            loaded=False
        )

        self.plugins[metadata.name] = plugin_info
        logger.info(f"Discovered plugin: {metadata.name} v{metadata.version}")

    def load_plugin(self, plugin_name: str) -> bool:
        """Load a specific plugin"""
        if plugin_name not in self.plugins:
            logger.error(f"Plugin not found: {plugin_name}")
            return False

        plugin_info = self.plugins[plugin_name]
        if plugin_info.loaded:
            logger.warning(f"Plugin already loaded: {plugin_name}")
            return True

        try:
            # Check dependencies
            if not self._check_dependencies(plugin_info.metadata):
                raise RuntimeError("Dependency check failed")

            # Load plugin module
            plugin_instance = self._load_plugin_module(plugin_info.metadata)

            # Validate
            if not plugin_instance.validate_config():
                raise RuntimeError("Configuration validation failed")

            # Call on_load hook
            plugin_instance.on_load()

            # Update plugin info
            plugin_info.plugin_instance = plugin_instance
            plugin_info.loaded = True
            plugin_info.enabled = True

            # Register hooks
            for hook_name in plugin_info.metadata.hooks:
                self.hooks[hook_name].append(plugin_name)

            logger.info(f"Loaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_name}: {e}")
            plugin_info.error = str(e)
            return False

    def _check_dependencies(self, metadata: PluginMetadata) -> bool:
        """Check if plugin dependencies are satisfied"""
        for dep in metadata.dependencies:
            try:
                importlib.import_module(dep)
            except ImportError:
                logger.error(f"Missing dependency: {dep}")
                return False
        return True

    def _load_plugin_module(self, metadata: PluginMetadata) -> PluginBase:
        """Load plugin Python module and instantiate"""
        # Parse entry point: "module.ClassName"
        module_name, class_name = metadata.entry_point.rsplit('.', 1)

        # Find plugin directory
        plugin_type_dir = self.plugins_dir / metadata.plugin_type
        plugin_dir = plugin_type_dir / metadata.name

        # Add plugin directory to path
        sys.path.insert(0, str(plugin_dir))

        try:
            # Import module
            module = importlib.import_module(module_name)

            # Get class
            plugin_class = getattr(module, class_name)

            # Instantiate
            plugin_instance = plugin_class(config=metadata.config_schema)

            return plugin_instance

        finally:
            # Remove from path
            if str(plugin_dir) in sys.path:
                sys.path.remove(str(plugin_dir))

    def unload_plugin(self, plugin_name: str) -> bool:
        """Unload a plugin"""
        if plugin_name not in self.plugins:
            logger.error(f"Plugin not found: {plugin_name}")
            return False

        plugin_info = self.plugins[plugin_name]
        if not plugin_info.loaded:
            logger.warning(f"Plugin not loaded: {plugin_name}")
            return True

        try:
            # Call on_unload hook
            if plugin_info.plugin_instance:
                plugin_info.plugin_instance.on_unload()

            # Unregister hooks
            for hook_name in plugin_info.metadata.hooks:
                if plugin_name in self.hooks[hook_name]:
                    self.hooks[hook_name].remove(plugin_name)

            # Update plugin info
            plugin_info.plugin_instance = None
            plugin_info.loaded = False
            plugin_info.enabled = False

            logger.info(f"Unloaded plugin: {plugin_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to unload plugin {plugin_name}: {e}")
            return False

    def execute_hook(self, hook: PluginHook, data: Any, context: Dict) -> Any:
        """Execute all plugins registered for a hook"""
        hook_name = hook.value
        result = data

        for plugin_name in self.hooks[hook_name]:
            plugin_info = self.plugins[plugin_name]

            if not plugin_info.enabled:
                continue

            try:
                logger.debug(f"Executing plugin {plugin_name} for hook {hook_name}")
                result = plugin_info.plugin_instance.execute(result, context)
            except Exception as e:
                logger.error(f"Plugin {plugin_name} failed: {e}")

        return result

    def execute_plugin(self, plugin_name: str, input_data: Any, context: Dict) -> Any:
        """Execute a specific plugin directly"""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin not found: {plugin_name}")

        plugin_info = self.plugins[plugin_name]
        if not plugin_info.loaded:
            raise RuntimeError(f"Plugin not loaded: {plugin_name}")

        return plugin_info.plugin_instance.execute(input_data, context)

    def list_plugins(self, plugin_type: Optional[PluginType] = None) -> List[Dict]:
        """List all plugins"""
        plugins_list = []

        for name, info in self.plugins.items():
            if plugin_type and info.metadata.plugin_type != plugin_type.value:
                continue

            plugins_list.append({
                'name': name,
                'version': info.metadata.version,
                'type': info.metadata.plugin_type,
                'author': info.metadata.author,
                'loaded': info.loaded,
                'enabled': info.enabled,
                'error': info.error
            })

        return plugins_list

    def get_plugin_info(self, plugin_name: str) -> Optional[PluginInfo]:
        """Get detailed plugin information"""
        return self.plugins.get(plugin_name)

    def create_plugin_template(self, name: str, plugin_type: PluginType, output_dir: Optional[Path] = None):
        """Create a plugin template"""
        if output_dir is None:
            output_dir = self.plugins_dir / plugin_type.value / name

        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate plugin.json
        metadata = {
            'name': name,
            'version': '1.0.0',
            'author': 'Your Name',
            'description': f'A {plugin_type.value} plugin',
            'plugin_type': plugin_type.value,
            'entry_point': f'{name.lower()}.{name}Plugin',
            'dependencies': [],
            'hooks': [],
            'supported_formats': []
        }

        with open(output_dir / 'plugin.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)

        # Generate plugin code template
        base_class = {
            PluginType.ANALYZER: 'AnalyzerPlugin',
            PluginType.DECOMPILER: 'DecompilerPlugin',
            PluginType.EXPORTER: 'ExporterPlugin',
        }.get(plugin_type, 'PluginBase')

        code_template = f'''#!/usr/bin/env python3
"""
{name} Plugin
Generated by REVENG Plugin System
"""

from plugin_system import {base_class}, PluginMetadata


class {name}Plugin({base_class}):
    """Custom {plugin_type.value} plugin"""

    def __init__(self, config=None):
        super().__init__(config)
        self.name = "{name}"
        self.version = "1.0.0"

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name=self.name,
            version=self.version,
            author="Your Name",
            description="A {plugin_type.value} plugin",
            plugin_type="{plugin_type.value}",
            entry_point="{name.lower()}.{name}Plugin"
        )

    def execute(self, input_data, context):
        """Execute plugin logic"""
        # TODO: Implement your plugin logic here
        return input_data

    def on_load(self):
        """Called when plugin is loaded"""
        print(f"{{self.name}} loaded!")

    def on_unload(self):
        """Called when plugin is unloaded"""
        print(f"{{self.name}} unloaded!")
'''

        with open(output_dir / f'{name.lower()}.py', 'w', encoding='utf-8') as f:
            f.write(code_template)

        # Generate README
        readme = f'''# {name} Plugin

## Description
{metadata['description']}

## Type
{plugin_type.value}

## Installation
1. Copy this directory to `plugins/{plugin_type.value}/{name}/`
2. Restart REVENG or reload plugins

## Configuration
Edit `plugin.json` to configure this plugin.

## Usage
```python
from plugin_system import PluginManager

manager = PluginManager()
manager.discover_plugins()
manager.load_plugin("{name}")
result = manager.execute_plugin("{name}", input_data, context)
```

## Development
Edit `{name.lower()}.py` to implement plugin logic.
'''

        with open(output_dir / 'README.md', 'w', encoding='utf-8') as f:
            f.write(readme)

        logger.info(f"Created plugin template: {output_dir}")


def main():
    """CLI interface for plugin system"""
    import argparse

    parser = argparse.ArgumentParser(
        description='REVENG plugin system for extensibility'
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # List plugins
    list_parser = subparsers.add_parser('list', help='List all plugins')
    list_parser.add_argument('--type', choices=[t.value for t in PluginType],
                            help='Filter by plugin type')

    # Create plugin
    create_parser = subparsers.add_parser('create', help='Create plugin template')
    create_parser.add_argument('name', help='Plugin name')
    create_parser.add_argument('--type', choices=[t.value for t in PluginType],
                              required=True, help='Plugin type')

    # Load plugin
    load_parser = subparsers.add_parser('load', help='Load a plugin')
    load_parser.add_argument('name', help='Plugin name')

    # Info
    info_parser = subparsers.add_parser('info', help='Show plugin info')
    info_parser.add_argument('name', help='Plugin name')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    manager = PluginManager()
    manager.discover_plugins()

    if args.command == 'list':
        plugin_type = PluginType(args.type) if args.type else None
        plugins = manager.list_plugins(plugin_type)
        print(json.dumps(plugins, indent=2))

    elif args.command == 'create':
        plugin_type = PluginType(args.type)
        manager.create_plugin_template(args.name, plugin_type)
        print(f"Created plugin template: plugins/{args.type}/{args.name}")

    elif args.command == 'load':
        success = manager.load_plugin(args.name)
        print(f"Plugin {args.name}: {'loaded' if success else 'failed'}")

    elif args.command == 'info':
        info = manager.get_plugin_info(args.name)
        if info:
            print(json.dumps(asdict(info.metadata), indent=2))
        else:
            print(f"Plugin not found: {args.name}")

    else:
        parser.print_help()

    return 0


if __name__ == '__main__':
    exit(main())
