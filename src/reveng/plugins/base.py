"""
Plugin Base Classes for REVENG

Base classes and interfaces for the REVENG plugin system.
"""

import os
import sys
import abc
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Type, Union
from dataclasses import dataclass
from enum import Enum

from ..core.errors import REVENGError, PluginError, create_error_context
from ..core.logger import get_logger

logger = get_logger()

class PluginCategory(Enum):
    """Plugin categories"""
    CORE_ANALYSIS = "core_analysis"
    MULTI_LANGUAGE = "multi_language"
    AI_ENHANCEMENT = "ai_enhancement"
    CODE_QUALITY = "code_quality"
    BINARY_OPERATIONS = "binary_operations"
    VISUALIZATION = "visualization"
    ENTERPRISE = "enterprise"
    ML_SECURITY = "ml_security"
    CONFIGURATION = "configuration"
    UTILITIES = "utilities"

class PluginStatus(Enum):
    """Plugin status"""
    ENABLED = "enabled"
    DISABLED = "disabled"
    LOADING = "loading"
    ERROR = "error"
    UNINSTALLED = "uninstalled"

class PluginPriority(Enum):
    """Plugin priority levels"""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    OPTIONAL = 5

@dataclass
class PluginMetadata:
    """Plugin metadata"""
    name: str
    version: str
    description: str
    author: str
    category: PluginCategory
    priority: PluginPriority
    dependencies: List[str] = None
    requirements: List[str] = None
    tags: List[str] = None
    homepage: Optional[str] = None
    license: Optional[str] = None
    min_reveng_version: Optional[str] = None
    max_reveng_version: Optional[str] = None

    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.requirements is None:
            self.requirements = []
        if self.tags is None:
            self.tags = []

@dataclass
class PluginContext:
    """Plugin execution context"""
    plugin_name: str
    binary_path: str
    output_dir: str
    config: Dict[str, Any] = None
    logger: Optional[logging.Logger] = None
    progress_callback: Optional[callable] = None

    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.logger is None:
            self.logger = get_logger()

class PluginBase(abc.ABC):
    """Base class for all REVENG plugins"""

    def __init__(self):
        self.metadata = self.get_metadata()
        self.status = PluginStatus.UNINSTALLED
        self.logger = get_logger()
        self._dependencies = {}
        self._dependents = set()

    @abc.abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        pass

    @abc.abstractmethod
    def initialize(self, context: PluginContext) -> bool:
        """Initialize the plugin"""
        pass

    @abc.abstractmethod
    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute the plugin's main functionality"""
        pass

    @abc.abstractmethod
    def cleanup(self, context: PluginContext) -> bool:
        """Cleanup plugin resources"""
        pass

    def validate_requirements(self, context: PluginContext) -> List[str]:
        """Validate plugin requirements"""
        errors = []

        # Check REVENG version compatibility
        if self.metadata.min_reveng_version:
            # This would be implemented with actual version checking
            pass

        if self.metadata.max_reveng_version:
            # This would be implemented with actual version checking
            pass

        # Check dependencies
        for dependency in self.metadata.dependencies:
            if not self._check_dependency(dependency):
                errors.append(f"Missing dependency: {dependency}")

        # Check requirements
        for requirement in self.metadata.requirements:
            if not self._check_requirement(requirement):
                errors.append(f"Missing requirement: {requirement}")

        return errors

    def _check_dependency(self, dependency: str) -> bool:
        """Check if a dependency is available"""
        # This would be implemented with actual dependency checking
        return True

    def _check_requirement(self, requirement: str) -> bool:
        """Check if a requirement is met"""
        # This would be implemented with actual requirement checking
        return True

    def get_dependencies(self) -> List[str]:
        """Get plugin dependencies"""
        return self.metadata.dependencies.copy()

    def get_dependents(self) -> List[str]:
        """Get plugins that depend on this one"""
        return list(self._dependents)

    def add_dependent(self, plugin_name: str):
        """Add a dependent plugin"""
        self._dependents.add(plugin_name)

    def remove_dependent(self, plugin_name: str):
        """Remove a dependent plugin"""
        self._dependents.discard(plugin_name)

    def set_status(self, status: PluginStatus):
        """Set plugin status"""
        self.status = status
        self.logger.info(f"Plugin {self.metadata.name} status changed to {status.value}")

    def get_status(self) -> PluginStatus:
        """Get plugin status"""
        return self.status

    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self.status == PluginStatus.ENABLED

    def is_available(self) -> bool:
        """Check if plugin is available for use"""
        return self.status in [PluginStatus.ENABLED, PluginStatus.LOADING]

    def get_priority(self) -> PluginPriority:
        """Get plugin priority"""
        return self.metadata.priority

    def get_category(self) -> PluginCategory:
        """Get plugin category"""
        return self.metadata.category

class AnalysisPlugin(PluginBase):
    """Base class for analysis plugins"""

    @abc.abstractmethod
    def analyze(self, context: PluginContext) -> Dict[str, Any]:
        """Perform analysis"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute analysis plugin"""
        try:
            self.logger.info(f"Executing analysis plugin: {self.metadata.name}")
            return self.analyze(context)
        except Exception as e:
            self.logger.error(f"Analysis plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"Analysis plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e

class VisualizationPlugin(PluginBase):
    """Base class for visualization plugins"""

    @abc.abstractmethod
    def visualize(self, context: PluginContext, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create visualization"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute visualization plugin"""
        try:
            self.logger.info(f"Executing visualization plugin: {self.metadata.name}")
            # Get data from context or previous plugins
            data = context.config.get('analysis_data', {})
            return self.visualize(context, data)
        except Exception as e:
            self.logger.error(f"Visualization plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"Visualization plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e

class ExportPlugin(PluginBase):
    """Base class for export plugins"""

    @abc.abstractmethod
    def export(self, context: PluginContext, data: Dict[str, Any]) -> Dict[str, Any]:
        """Export data"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute export plugin"""
        try:
            self.logger.info(f"Executing export plugin: {self.metadata.name}")
            # Get data from context or previous plugins
            data = context.config.get('analysis_data', {})
            return self.export(context, data)
        except Exception as e:
            self.logger.error(f"Export plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"Export plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e

class UtilityPlugin(PluginBase):
    """Base class for utility plugins"""

    @abc.abstractmethod
    def utility_function(self, context: PluginContext) -> Dict[str, Any]:
        """Perform utility function"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute utility plugin"""
        try:
            self.logger.info(f"Executing utility plugin: {self.metadata.name}")
            return self.utility_function(context)
        except Exception as e:
            self.logger.error(f"Utility plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"Utility plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e

class AIPlugin(PluginBase):
    """Base class for AI enhancement plugins"""

    @abc.abstractmethod
    def ai_enhance(self, context: PluginContext, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply AI enhancement"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute AI plugin"""
        try:
            self.logger.info(f"Executing AI plugin: {self.metadata.name}")
            # Get data from context or previous plugins
            data = context.config.get('analysis_data', {})
            return self.ai_enhance(context, data)
        except Exception as e:
            self.logger.error(f"AI plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"AI plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e

class SecurityPlugin(PluginBase):
    """Base class for security plugins"""

    @abc.abstractmethod
    def security_analysis(self, context: PluginContext) -> Dict[str, Any]:
        """Perform security analysis"""
        pass

    def execute(self, context: PluginContext) -> Dict[str, Any]:
        """Execute security plugin"""
        try:
            self.logger.info(f"Executing security plugin: {self.metadata.name}")
            return self.security_analysis(context)
        except Exception as e:
            self.logger.error(f"Security plugin {self.metadata.name} failed: {e}")
            raise PluginError(f"Security plugin {self.metadata.name} failed", plugin_name=self.metadata.name) from e
