"""
REVENG Core Exceptions
=====================

Standardized exception hierarchy for the REVENG platform.
Provides clear error categorization and handling.

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

class REVENGException(Exception):
    """Base exception for all REVENG errors."""

    def __init__(self, message: str, error_code: str = None, details: dict = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def __str__(self):
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

class AnalysisError(REVENGException):
    """Raised when analysis operations fail."""

    def __init__(self, message: str, analysis_step: str = None, **kwargs):
        super().__init__(message, error_code="ANALYSIS_ERROR", **kwargs)
        self.analysis_step = analysis_step

class DependencyError(REVENGException):
    """Raised when required dependencies are missing or incompatible."""

    def __init__(self, message: str, missing_dependency: str = None, **kwargs):
        super().__init__(message, error_code="DEPENDENCY_ERROR", **kwargs)
        self.missing_dependency = missing_dependency

class ValidationError(REVENGException):
    """Raised when input validation fails."""

    def __init__(self, message: str, field: str = None, **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)
        self.field = field

class SecurityError(REVENGException):
    """Raised when security constraints are violated."""

    def __init__(self, message: str, security_issue: str = None, **kwargs):
        super().__init__(message, error_code="SECURITY_ERROR", **kwargs)
        self.security_issue = security_issue

class ConfigurationError(REVENGException):
    """Raised when configuration is invalid."""

    def __init__(self, message: str, config_key: str = None, **kwargs):
        super().__init__(message, error_code="CONFIG_ERROR", **kwargs)
        self.config_key = config_key

class ToolError(REVENGException):
    """Raised when external tools fail."""

    def __init__(self, message: str, tool_name: str = None, exit_code: int = None, **kwargs):
        super().__init__(message, error_code="TOOL_ERROR", **kwargs)
        self.tool_name = tool_name
        self.exit_code = exit_code

class MLModelError(REVENGException):
    """Raised when ML model operations fail."""

    def __init__(self, message: str, model_name: str = None, **kwargs):
        super().__init__(message, error_code="ML_MODEL_ERROR", **kwargs)
        self.model_name = model_name

class BinaryFormatError(REVENGException):
    """Raised when binary format is unsupported or corrupted."""

    def __init__(self, message: str, format_type: str = None, **kwargs):
        super().__init__(message, error_code="BINARY_FORMAT_ERROR", **kwargs)
        self.format_type = format_type

class TimeoutError(REVENGException):
    """Raised when operations exceed timeout."""

    def __init__(self, message: str, timeout_seconds: int = None, **kwargs):
        super().__init__(message, error_code="TIMEOUT_ERROR", **kwargs)
        self.timeout_seconds = timeout_seconds

class InsufficientPermissionsError(REVENGException):
    """Raised when insufficient permissions for operation."""

    def __init__(self, message: str, required_permission: str = None, **kwargs):
        super().__init__(message, error_code="PERMISSIONS_ERROR", **kwargs)
        self.required_permission = required_permission

class ResourceError(REVENGException):
    """Raised when system resources are insufficient."""

    def __init__(self, message: str, resource_type: str = None, **kwargs):
        super().__init__(message, error_code="RESOURCE_ERROR", **kwargs)
        self.resource_type = resource_type

# Convenience functions for common error patterns
def raise_analysis_error(message: str, step: str = None, **kwargs):
    """Raise an AnalysisError with optional step information."""
    raise AnalysisError(message, analysis_step=step, **kwargs)

def raise_dependency_error(message: str, dependency: str = None, **kwargs):
    """Raise a DependencyError with optional dependency information."""
    raise DependencyError(message, missing_dependency=dependency, **kwargs)

def raise_validation_error(message: str, field: str = None, **kwargs):
    """Raise a ValidationError with optional field information."""
    raise ValidationError(message, field=field, **kwargs)

def raise_security_error(message: str, issue: str = None, **kwargs):
    """Raise a SecurityError with optional issue information."""
    raise SecurityError(message, security_issue=issue, **kwargs)

def raise_tool_error(message: str, tool: str = None, exit_code: int = None, **kwargs):
    """Raise a ToolError with optional tool and exit code information."""
    raise ToolError(message, tool_name=tool, exit_code=exit_code, **kwargs)
