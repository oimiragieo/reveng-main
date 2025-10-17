"""
Plugin Manager for REVENG

Manages plugin loading, dependency resolution, and execution.
"""

import os
import sys
import importlib
import inspect
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Type, Union, Set
from dataclasses import dataclass
from enum import Enum

from .base import PluginBase, PluginMetadata, PluginContext, PluginCategory, PluginStatus, PluginPriority
from ..core.errors import REVENGError, PluginError, create_error_context
from ..core.logger import get_logger

logger = get_logger()

@dataclass
class PluginInfo:
    """Plugin information"""
    name: str
    plugin_class: Type[PluginBase]
    metadata: PluginMetadata
    status: PluginStatus
    instance: Optional[PluginBase] = None
    load_time: float = 0.0
    error_message: Optional[str] = None

class PluginManager:
    """Manages REVENG plugins"""

    def __init__(self, plugin_dirs: Optional[List[str]] = None):
        self.logger = get_logger()
        self.plugins: Dict[str, PluginInfo] = {}
        self.plugin_dirs = plugin_dirs or self._get_default_plugin_dirs()
        self.dependency_graph: Dict[str, Set[str]] = {}
        self.execution_order: List[str] = []

        # Load plugins
        self._load_plugins()
        self._resolve_dependencies()
        self._calculate_execution_order()

    def _get_default_plugin_dirs(self) -> List[str]:
        """Get default plugin directories"""
        return [
            str(Path(__file__).parent / "core"),
            str(Path(__file__).parent / "analysis"),
            str(Path(__file__).parent / "visualization"),
            str(Path(__file__).parent / "export"),
            str(Path(__file__).parent / "ai"),
            str(Path(__file__).parent / "security"),
            str(Path(__file__).parent / "utilities")
        ]

    def _load_plugins(self):
        """Load all available plugins"""

        for plugin_dir in self.plugin_dirs:
            if not Path(plugin_dir).exists():
                self.logger.warning(f"Plugin directory not found: {plugin_dir}")
                continue

            self.logger.info(f"Loading plugins from: {plugin_dir}")

            # Add to Python path
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)

            # Scan for Python files
            for py_file in Path(plugin_dir).glob("*.py"):
                if py_file.name.startswith("__"):
                    continue

                try:
                    self._load_plugin_from_file(py_file)
                except Exception as e:
                    self.logger.error(f"Failed to load plugin from {py_file}: {e}")

    def _load_plugin_from_file(self, py_file: Path):
        """Load plugin from Python file"""

        try:
            # Import module
            module_name = py_file.stem
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin classes
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, PluginBase) and
                    obj != PluginBase and
                    not inspect.isabstract(obj)):

                    # Create plugin instance
                    plugin_instance = obj()
                    metadata = plugin_instance.get_metadata()

                    # Check if plugin already exists
                    if metadata.name in self.plugins:
                        self.logger.warning(f"Plugin {metadata.name} already loaded, skipping")
                        continue

                    # Create plugin info
                    plugin_info = PluginInfo(
                        name=metadata.name,
                        plugin_class=obj,
                        metadata=metadata,
                        status=PluginStatus.UNINSTALLED,
                        instance=plugin_instance
                    )

                    self.plugins[metadata.name] = plugin_info
                    self.logger.info(f"Loaded plugin: {metadata.name} v{metadata.version}")

        except Exception as e:
            self.logger.error(f"Failed to load plugin from {py_file}: {e}")
            raise

    def _resolve_dependencies(self):
        """Resolve plugin dependencies"""

        # Build dependency graph
        for plugin_name, plugin_info in self.plugins.items():
            self.dependency_graph[plugin_name] = set(plugin_info.metadata.dependencies)

        # Check for circular dependencies
        self._check_circular_dependencies()

        # Validate dependencies
        for plugin_name, dependencies in self.dependency_graph.items():
            for dependency in dependencies:
                if dependency not in self.plugins:
                    self.logger.error(f"Plugin {plugin_name} depends on unknown plugin: {dependency}")
                    self.plugins[plugin_name].status = PluginStatus.ERROR
                    self.plugins[plugin_name].error_message = f"Missing dependency: {dependency}"

    def _check_circular_dependencies(self):
        """Check for circular dependencies"""

        def has_cycle(plugin: str, visited: Set[str], rec_stack: Set[str]) -> bool:
            visited.add(plugin)
            rec_stack.add(plugin)

            for dependency in self.dependency_graph.get(plugin, set()):
                if dependency not in visited:
                    if has_cycle(dependency, visited, rec_stack):
                        return True
                elif dependency in rec_stack:
                    return True

            rec_stack.remove(plugin)
            return False

        for plugin in self.plugins:
            if plugin not in [p for p in self.plugins.values() if p.status == PluginStatus.ERROR]:
                if has_cycle(plugin, set(), set()):
                    self.logger.error(f"Circular dependency detected involving plugin: {plugin}")
                    self.plugins[plugin].status = PluginStatus.ERROR
                    self.plugins[plugin].error_message = "Circular dependency detected"

    def _calculate_execution_order(self):
        """Calculate plugin execution order based on dependencies and priority"""

        # Topological sort with priority consideration
        visited = set()
        temp_visited = set()
        execution_order = []

        def visit(plugin_name: str):
            if plugin_name in temp_visited:
                raise REVENGError(f"Circular dependency detected: {plugin_name}")
            if plugin_name in visited:
                return

            temp_visited.add(plugin_name)

            # Visit dependencies first
            for dependency in self.dependency_graph.get(plugin_name, set()):
                if dependency in self.plugins:
                    visit(dependency)

            temp_visited.remove(plugin_name)
            visited.add(plugin_name)
            execution_order.append(plugin_name)

        # Visit all plugins
        for plugin_name in self.plugins:
            if plugin_name not in visited:
                try:
                    visit(plugin_name)
                except REVENGError as e:
                    self.logger.error(f"Failed to calculate execution order: {e}")
                    continue

        # Sort by priority within each dependency level
        priority_sorted = []
        for plugin_name in execution_order:
            plugin_info = self.plugins[plugin_name]
            priority_sorted.append((plugin_name, plugin_info.metadata.priority.value))

        priority_sorted.sort(key=lambda x: x[1])
        self.execution_order = [name for name, _ in priority_sorted]

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        """Get plugin by name"""
        return self.plugins.get(name)

    def get_plugins_by_category(self, category: PluginCategory) -> List[PluginInfo]:
        """Get plugins by category"""
        return [
            plugin_info for plugin_info in self.plugins.values()
            if plugin_info.metadata.category == category
        ]

    def get_enabled_plugins(self) -> List[PluginInfo]:
        """Get enabled plugins"""
        return [
            plugin_info for plugin_info in self.plugins.values()
            if plugin_info.status == PluginStatus.ENABLED
        ]

    def get_plugins_by_priority(self, priority: PluginPriority) -> List[PluginInfo]:
        """Get plugins by priority"""
        return [
            plugin_info for plugin_info in self.plugins.values()
            if plugin_info.metadata.priority == priority
        ]

    def enable_plugin(self, name: str) -> bool:
        """Enable a plugin"""

        if name not in self.plugins:
            self.logger.error(f"Plugin not found: {name}")
            return False

        plugin_info = self.plugins[name]

        if plugin_info.status == PluginStatus.ERROR:
            self.logger.error(f"Cannot enable plugin {name}: {plugin_info.error_message}")
            return False

        # Check dependencies
        for dependency in plugin_info.metadata.dependencies:
            if dependency not in self.plugins:
                self.logger.error(f"Plugin {name} depends on missing plugin: {dependency}")
                return False

            dep_plugin = self.plugins[dependency]
            if dep_plugin.status != PluginStatus.ENABLED:
                self.logger.error(f"Plugin {name} depends on disabled plugin: {dependency}")
                return False

        plugin_info.status = PluginStatus.ENABLED
        self.logger.info(f"Enabled plugin: {name}")
        return True

    def disable_plugin(self, name: str) -> bool:
        """Disable a plugin"""

        if name not in self.plugins:
            self.logger.error(f"Plugin not found: {name}")
            return False

        plugin_info = self.plugins[name]

        # Check if other plugins depend on this one
        dependents = [p for p in self.plugins.values() if name in p.metadata.dependencies and p.status == PluginStatus.ENABLED]
        if dependents:
            self.logger.error(f"Cannot disable plugin {name}: {len(dependents)} plugins depend on it")
            return False

        plugin_info.status = PluginStatus.DISABLED
        self.logger.info(f"Disabled plugin: {name}")
        return True

    def execute_plugin(self, name: str, context: PluginContext) -> Dict[str, Any]:
        """Execute a plugin"""

        if name not in self.plugins:
            raise PluginError(f"Plugin not found: {name}", plugin_name=name)

        plugin_info = self.plugins[name]

        if plugin_info.status != PluginStatus.ENABLED:
            raise PluginError(f"Plugin {name} is not enabled", plugin_name=name)

        if not plugin_info.instance:
            raise PluginError(f"Plugin {name} instance not available", plugin_name=name)

        try:
            self.logger.info(f"Executing plugin: {name}")
            return plugin_info.instance.execute(context)
        except Exception as e:
            self.logger.error(f"Plugin {name} execution failed: {e}")
            raise PluginError(f"Plugin {name} execution failed", plugin_name=name) from e

    def execute_plugin_chain(self, context: PluginContext, plugin_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute a chain of plugins"""

        if plugin_names is None:
            plugin_names = self.execution_order

        results = {}

        for plugin_name in plugin_names:
            if plugin_name not in self.plugins:
                self.logger.warning(f"Plugin not found: {plugin_name}")
                continue

            plugin_info = self.plugins[plugin_name]
            if plugin_info.status != PluginStatus.ENABLED:
                self.logger.warning(f"Plugin {plugin_name} is not enabled")
                continue

            try:
                plugin_result = self.execute_plugin(plugin_name, context)
                results[plugin_name] = plugin_result

                # Update context with plugin result
                context.config[f"{plugin_name}_result"] = plugin_result

            except Exception as e:
                self.logger.error(f"Plugin chain execution failed at {plugin_name}: {e}")
                results[plugin_name] = {"error": str(e)}

        return results

    def get_plugin_status(self, name: str) -> Optional[PluginStatus]:
        """Get plugin status"""
        plugin_info = self.plugins.get(name)
        return plugin_info.status if plugin_info else None

    def get_plugin_metadata(self, name: str) -> Optional[PluginMetadata]:
        """Get plugin metadata"""
        plugin_info = self.plugins.get(name)
        return plugin_info.metadata if plugin_info else None

    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins"""
        return [
            {
                "name": plugin_info.name,
                "version": plugin_info.metadata.version,
                "description": plugin_info.metadata.description,
                "author": plugin_info.metadata.author,
                "category": plugin_info.metadata.category.value,
                "priority": plugin_info.metadata.priority.value,
                "status": plugin_info.status.value,
                "dependencies": plugin_info.metadata.dependencies,
                "error_message": plugin_info.error_message
            }
            for plugin_info in self.plugins.values()
        ]

    def validate_plugin(self, name: str) -> List[str]:
        """Validate plugin requirements"""

        if name not in self.plugins:
            return [f"Plugin not found: {name}"]

        plugin_info = self.plugins[name]
        if not plugin_info.instance:
            return [f"Plugin instance not available: {name}"]

        context = PluginContext(
            plugin_name=name,
            binary_path="",
            output_dir="",
            config={}
        )

        return plugin_info.instance.validate_requirements(context)

    def get_dependency_tree(self, name: str) -> Dict[str, Any]:
        """Get plugin dependency tree"""

        if name not in self.plugins:
            return {}

        def build_tree(plugin_name: str, visited: Set[str] = None) -> Dict[str, Any]:
            if visited is None:
                visited = set()

            if plugin_name in visited:
                return {"name": plugin_name, "circular": True}

            visited.add(plugin_name)

            plugin_info = self.plugins[plugin_name]
            tree = {
                "name": plugin_name,
                "version": plugin_info.metadata.version,
                "status": plugin_info.status.value,
                "dependencies": []
            }

            for dependency in plugin_info.metadata.dependencies:
                if dependency in self.plugins:
                    tree["dependencies"].append(build_tree(dependency, visited.copy()))

            return tree

        return build_tree(name)

    def reload_plugin(self, name: str) -> bool:
        """Reload a plugin"""

        if name not in self.plugins:
            self.logger.error(f"Plugin not found: {name}")
            return False

        plugin_info = self.plugins[name]

        try:
            # Disable plugin first
            if plugin_info.status == PluginStatus.ENABLED:
                self.disable_plugin(name)

            # Reload plugin class
            plugin_class = plugin_info.plugin_class
            importlib.reload(plugin_class.__module__)

            # Create new instance
            plugin_info.instance = plugin_class()
            plugin_info.metadata = plugin_info.instance.get_metadata()

            # Re-enable if it was enabled
            if plugin_info.status == PluginStatus.DISABLED:
                self.enable_plugin(name)

            self.logger.info(f"Reloaded plugin: {name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to reload plugin {name}: {e}")
            return False
