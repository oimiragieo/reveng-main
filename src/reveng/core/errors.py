"""
REVENG Enhanced Error Handling System

Structured error system with context and recovery suggestions.
"""

import traceback
import sys
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

class ErrorSeverity(Enum):
    """Error severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class ErrorContext:
    """Context information for errors"""
    component: str
    operation: str
    binary_path: Optional[str] = None
    tool_name: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None

@dataclass
class RecoverySuggestion:
    """Recovery suggestion for errors"""
    action: str
    description: str
    command: Optional[str] = None
    auto_fixable: bool = False

class REVENGError(Exception):
    """Base exception with context and recovery suggestions"""

    def __init__(
        self,
        message: str,
        context: Optional[ErrorContext] = None,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        recovery_suggestions: Optional[List[RecoverySuggestion]] = None,
        original_exception: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.context = context or ErrorContext("unknown", "unknown")
        self.severity = severity
        self.recovery_suggestions = recovery_suggestions or []
        self.original_exception = original_exception
        self.timestamp = self._get_timestamp()
        self.stack_trace = self._get_stack_trace()

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def _get_stack_trace(self) -> str:
        """Get stack trace"""
        return traceback.format_exc()

    def get_detailed_message(self) -> str:
        """Get detailed error message with context"""
        details = [f"Error: {self.message}"]

        if self.context:
            details.append(f"Component: {self.context.component}")
            details.append(f"Operation: {self.context.operation}")
            if self.context.binary_path:
                details.append(f"Binary: {self.context.binary_path}")
            if self.context.tool_name:
                details.append(f"Tool: {self.context.tool_name}")

        if self.recovery_suggestions:
            details.append("Recovery suggestions:")
            for i, suggestion in enumerate(self.recovery_suggestions, 1):
                details.append(f"  {i}. {suggestion.description}")
                if suggestion.command:
                    details.append(f"     Command: {suggestion.command}")

        return "\n".join(details)

    def get_recovery_commands(self) -> List[str]:
        """Get recovery commands"""
        return [
            suggestion.command for suggestion in self.recovery_suggestions
            if suggestion.command
        ]

    def is_auto_fixable(self) -> bool:
        """Check if error can be auto-fixed"""
        return any(suggestion.auto_fixable for suggestion in self.recovery_suggestions)

class MissingDependencyError(REVENGError):
    """Missing tool dependency error"""

    def __init__(
        self,
        tool_name: str,
        context: Optional[ErrorContext] = None,
        install_command: Optional[str] = None
    ):
        message = f"Missing dependency: {tool_name}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="install_tool",
                description=f"Install {tool_name} using dependency manager",
                command=f"reveng setup install-deps --tools {tool_name}",
                auto_fixable=True
            )
        ]

        if install_command:
            recovery_suggestions.append(
                RecoverySuggestion(
                    action="manual_install",
                    description=f"Manual installation: {install_command}",
                    command=install_command,
                    auto_fixable=False
                )
            )

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions
        )

        self.tool_name = tool_name

class AnalysisFailureError(REVENGError):
    """Analysis operation failed"""

    def __init__(
        self,
        analysis_type: str,
        binary_path: str,
        context: Optional[ErrorContext] = None,
        fallback_available: bool = False,
        original_exception: Optional[Exception] = None
    ):
        message = f"Analysis failed: {analysis_type} on {binary_path}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="retry_analysis",
                description="Retry the analysis operation",
                command=f"reveng analyze {binary_path} --retry",
                auto_fixable=True
            )
        ]

        if fallback_available:
            recovery_suggestions.append(
                RecoverySuggestion(
                    action="use_fallback",
                    description="Use fallback analysis method",
                    command=f"reveng analyze {binary_path} --fallback",
                    auto_fixable=True
                )
            )

        recovery_suggestions.extend([
            RecoverySuggestion(
                action="check_binary",
                description="Verify binary file is not corrupted",
                command=f"file {binary_path}",
                auto_fixable=False
            ),
            RecoverySuggestion(
                action="check_permissions",
                description="Check file permissions",
                command=f"ls -la {binary_path}",
                auto_fixable=False
            )
        ])

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions,
            original_exception=original_exception
        )

        self.analysis_type = analysis_type
        self.binary_path = binary_path

class BinaryFormatError(REVENGError):
    """Unsupported binary format"""

    def __init__(
        self,
        binary_path: str,
        detected_format: str,
        supported_formats: List[str],
        context: Optional[ErrorContext] = None
    ):
        message = f"Unsupported binary format: {detected_format} (supported: {', '.join(supported_formats)})"

        recovery_suggestions = [
            RecoverySuggestion(
                action="convert_binary",
                description="Convert binary to supported format",
                command="Use appropriate conversion tool",
                auto_fixable=False
            ),
            RecoverySuggestion(
                action="use_hex_editor",
                description="Use hex editor for manual analysis",
                command=f"reveng hex {binary_path}",
                auto_fixable=True
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.WARNING,
            recovery_suggestions=recovery_suggestions
        )

        self.binary_path = binary_path
        self.detected_format = detected_format
        self.supported_formats = supported_formats

class PackedBinaryError(REVENGError):
    """Binary is packed/obfuscated"""

    def __init__(
        self,
        binary_path: str,
        packer_type: str,
        confidence: float,
        context: Optional[ErrorContext] = None
    ):
        message = f"Binary is packed with {packer_type} (confidence: {confidence:.2f})"

        recovery_suggestions = [
            RecoverySuggestion(
                action="unpack_binary",
                description="Attempt to unpack the binary",
                command=f"reveng malware unpack {binary_path}",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="detect_packer",
                description="Get more information about the packer",
                command=f"reveng malware detect-packer {binary_path}",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="manual_unpack",
                description="Manual unpacking with debugger",
                command="Use x64dbg or similar debugger",
                auto_fixable=False
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.WARNING,
            recovery_suggestions=recovery_suggestions
        )

        self.binary_path = binary_path
        self.packer_type = packer_type
        self.confidence = confidence

class MemoryAnalysisError(REVENGError):
    """Memory forensics failed"""

    def __init__(
        self,
        process_id: int,
        operation: str,
        context: Optional[ErrorContext] = None,
        original_exception: Optional[Exception] = None
    ):
        message = f"Memory analysis failed for process {process_id}: {operation}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="check_permissions",
                description="Check if running with sufficient privileges",
                command="Run as administrator",
                auto_fixable=False
            ),
            RecoverySuggestion(
                action="retry_analysis",
                description="Retry memory analysis",
                command=f"reveng malware memory {process_id} --retry",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="use_alternative",
                description="Use alternative memory analysis tool",
                command="Use Volatility or similar tool",
                auto_fixable=False
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions,
            original_exception=original_exception
        )

        self.process_id = process_id
        self.operation = operation

class ScriptExecutionError(REVENGError):
    """Ghidra/IDA script execution failed"""

    def __init__(
        self,
        script_path: str,
        tool_name: str,
        context: Optional[ErrorContext] = None,
        original_exception: Optional[Exception] = None
    ):
        message = f"Script execution failed: {script_path} in {tool_name}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="check_script",
                description="Verify script syntax and dependencies",
                command=f"python -m py_compile {script_path}",
                auto_fixable=False
            ),
            RecoverySuggestion(
                action="retry_execution",
                description="Retry script execution",
                command=f"reveng ghidra script {script_path} --retry",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="manual_execution",
                description="Execute script manually in {tool_name}",
                command=f"Load script in {tool_name} GUI",
                auto_fixable=False
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions,
            original_exception=original_exception
        )

        self.script_path = script_path
        self.tool_name = tool_name

class PipelineExecutionError(REVENGError):
    """Pipeline execution failed"""

    def __init__(
        self,
        pipeline_name: str,
        stage_name: str,
        context: Optional[ErrorContext] = None,
        original_exception: Optional[Exception] = None
    ):
        message = f"Pipeline execution failed: {pipeline_name} at stage {stage_name}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="retry_pipeline",
                description="Retry pipeline execution",
                command=f"reveng pipeline run {pipeline_name} --retry",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="skip_stage",
                description="Skip failed stage and continue",
                command=f"reveng pipeline run {pipeline_name} --skip {stage_name}",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="debug_pipeline",
                description="Debug pipeline execution",
                command=f"reveng pipeline debug {pipeline_name}",
                auto_fixable=False
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions,
            original_exception=original_exception
        )

        self.pipeline_name = pipeline_name
        self.stage_name = stage_name

class ConfigurationError(REVENGError):
    """Configuration error"""

    def __init__(
        self,
        config_key: str,
        expected_type: str,
        actual_value: Any,
        context: Optional[ErrorContext] = None
    ):
        message = f"Configuration error: {config_key} expected {expected_type}, got {type(actual_value).__name__}"

        recovery_suggestions = [
            RecoverySuggestion(
                action="fix_config",
                description="Fix configuration value",
                command=f"reveng config set {config_key} <correct_value>",
                auto_fixable=True
            ),
            RecoverySuggestion(
                action="reset_config",
                description="Reset configuration to defaults",
                command="reveng config reset",
                auto_fixable=True
            )
        ]

        super().__init__(
            message=message,
            context=context,
            severity=ErrorSeverity.ERROR,
            recovery_suggestions=recovery_suggestions
        )

        self.config_key = config_key
        self.expected_type = expected_type
        self.actual_value = actual_value

def create_error_context(
    component: str,
    operation: str,
    binary_path: Optional[str] = None,
    tool_name: Optional[str] = None,
    **kwargs
) -> ErrorContext:
    """Create error context"""
    return ErrorContext(
        component=component,
        operation=operation,
        binary_path=binary_path,
        tool_name=tool_name,
        additional_info=kwargs if kwargs else None
    )

def handle_exception(
    exception: Exception,
    context: Optional[ErrorContext] = None,
    reraise: bool = True
) -> REVENGError:
    """Convert generic exception to REVENG error"""

    if isinstance(exception, REVENGError):
        return exception

    # Convert common exceptions to REVENG errors
    if isinstance(exception, FileNotFoundError):
        return MissingDependencyError(
            tool_name="unknown",
            context=context,
            install_command="Check if tool is installed"
        )

    if isinstance(exception, PermissionError):
        return AnalysisFailureError(
            analysis_type="file_access",
            binary_path=context.binary_path if context else "unknown",
            context=context,
            original_exception=exception
        )

    if isinstance(exception, subprocess.CalledProcessError):
        return ScriptExecutionError(
            script_path="unknown",
            tool_name=context.tool_name if context else "unknown",
            context=context,
            original_exception=exception
        )

    # Generic error
    return REVENGError(
        message=str(exception),
        context=context,
        severity=ErrorSeverity.ERROR,
        original_exception=exception
    )

def log_error(error: REVENGError, logger) -> None:
    """Log REVENG error with context"""
    logger.error(f"REVENG Error: {error.message}")
    logger.error(f"Context: {error.context.component}.{error.context.operation}")

    if error.context.binary_path:
        logger.error(f"Binary: {error.context.binary_path}")

    if error.recovery_suggestions:
        logger.info("Recovery suggestions:")
        for suggestion in error.recovery_suggestions:
            logger.info(f"  - {suggestion.description}")
            if suggestion.command:
                logger.info(f"    Command: {suggestion.command}")

    if error.original_exception:
        logger.debug(f"Original exception: {error.original_exception}")
        logger.debug(f"Stack trace: {error.stack_trace}")

# Import subprocess for error handling
import subprocess
