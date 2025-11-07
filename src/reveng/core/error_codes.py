"""
REVENG Error Code System

Standardized error codes for structured error reporting and agent-friendly APIs.
Error codes follow the format: {CATEGORY}_{SPECIFIC_ERROR}

Categories:
- BINARY_: Binary file related errors
- TOOL_: External tool availability/execution errors
- ANALYSIS_: Analysis step failures
- CONFIG_: Configuration errors
- NETWORK_: Network/download errors
- VALIDATION_: Validation failures
"""

from enum import Enum
from typing import Dict, Any


class ErrorCode(Enum):
    """Standardized error codes for REVENG"""

    # Binary File Errors (1000-1099)
    BINARY_NOT_FOUND = "BINARY_NOT_FOUND"
    BINARY_NOT_READABLE = "BINARY_NOT_READABLE"
    BINARY_INVALID_FORMAT = "BINARY_INVALID_FORMAT"
    BINARY_UNSUPPORTED_FORMAT = "BINARY_UNSUPPORTED_FORMAT"

    # Tool Availability Errors (1100-1199)
    TOOL_NOT_INSTALLED = "TOOL_NOT_INSTALLED"
    TOOL_JAVA_NOT_FOUND = "TOOL_JAVA_NOT_FOUND"
    TOOL_JAVA_VERSION_MISMATCH = "TOOL_JAVA_VERSION_MISMATCH"
    TOOL_GHIDRA_NOT_FOUND = "TOOL_GHIDRA_NOT_FOUND"
    TOOL_GHIDRA_SERVER_UNAVAILABLE = "TOOL_GHIDRA_SERVER_UNAVAILABLE"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"

    # Analysis Errors (1200-1299)
    ANALYSIS_STEP_FAILED = "ANALYSIS_STEP_FAILED"
    ANALYSIS_TIMEOUT = "ANALYSIS_TIMEOUT"
    ANALYSIS_PARTIAL_FAILURE = "ANALYSIS_PARTIAL_FAILURE"
    ANALYSIS_UNSUPPORTED_OPERATION = "ANALYSIS_UNSUPPORTED_OPERATION"

    # Configuration Errors (1300-1399)
    CONFIG_FILE_NOT_FOUND = "CONFIG_FILE_NOT_FOUND"
    CONFIG_INVALID_FORMAT = "CONFIG_INVALID_FORMAT"
    CONFIG_MISSING_REQUIRED_FIELD = "CONFIG_MISSING_REQUIRED_FIELD"

    # Network/Download Errors (1400-1499)
    NETWORK_CONNECTION_FAILED = "NETWORK_CONNECTION_FAILED"
    NETWORK_DOWNLOAD_FAILED = "NETWORK_DOWNLOAD_FAILED"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    NETWORK_CHECKSUM_MISMATCH = "NETWORK_CHECKSUM_MISMATCH"

    # Validation Errors (1500-1599)
    VALIDATION_FAILED = "VALIDATION_FAILED"
    VALIDATION_CHECKSUM_MISMATCH = "VALIDATION_CHECKSUM_MISMATCH"

    # ML/AI Errors (1600-1699)
    ML_MODEL_NOT_AVAILABLE = "ML_MODEL_NOT_AVAILABLE"
    ML_INFERENCE_FAILED = "ML_INFERENCE_FAILED"
    ML_UNSUPPORTED_OPERATION = "ML_UNSUPPORTED_OPERATION"

    # Generic Errors (1900-1999)
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# Error code metadata with user-friendly messages and recovery suggestions
ERROR_METADATA: Dict[ErrorCode, Dict[str, Any]] = {
    ErrorCode.BINARY_NOT_FOUND: {
        "severity": "critical",
        "message": "Binary file not found",
        "recovery": "Provide a valid binary file path or place a binary in the current directory",
    },
    ErrorCode.BINARY_NOT_READABLE: {
        "severity": "critical",
        "message": "Binary file cannot be read",
        "recovery": "Check file permissions and ensure the file is not corrupted",
    },
    ErrorCode.BINARY_INVALID_FORMAT: {
        "severity": "critical",
        "message": "Binary file has an invalid format",
        "recovery": "Ensure the file is a valid executable binary (PE/ELF/Mach-O/DEX/JAR)",
    },
    ErrorCode.TOOL_NOT_INSTALLED: {
        "severity": "warning",
        "message": "Required tool is not installed",
        "recovery": "Install the tool or allow REVENG to auto-install it",
    },
    ErrorCode.TOOL_JAVA_NOT_FOUND: {
        "severity": "warning",
        "message": "Java runtime not found",
        "recovery": "Install Java 17+ or add it to your system PATH",
    },
    ErrorCode.TOOL_JAVA_VERSION_MISMATCH: {
        "severity": "warning",
        "message": "Java version incompatible with required tools",
        "recovery": "Upgrade to Java 17+ for full Ghidra compatibility",
    },
    ErrorCode.TOOL_GHIDRA_NOT_FOUND: {
        "severity": "warning",
        "message": "Ghidra not found",
        "recovery": "Install Ghidra or allow REVENG to download it automatically",
    },
    ErrorCode.TOOL_GHIDRA_SERVER_UNAVAILABLE: {
        "severity": "warning",
        "message": "Ghidra Analysis Server is not available",
        "recovery": "Start the Ghidra Analysis Server or analysis will continue with limited capabilities",
    },
    ErrorCode.TOOL_EXECUTION_FAILED: {
        "severity": "error",
        "message": "External tool execution failed",
        "recovery": "Check tool installation and permissions",
    },
    ErrorCode.ANALYSIS_STEP_FAILED: {
        "severity": "error",
        "message": "Analysis step failed",
        "recovery": "Check logs for details; analysis will continue with next step",
    },
    ErrorCode.ANALYSIS_TIMEOUT: {
        "severity": "error",
        "message": "Analysis step timed out",
        "recovery": "Increase timeout value in configuration or simplify the binary",
    },
    ErrorCode.ANALYSIS_PARTIAL_FAILURE: {
        "severity": "warning",
        "message": "Analysis completed with partial failures",
        "recovery": "Review step results for details on which steps succeeded",
    },
    ErrorCode.CONFIG_FILE_NOT_FOUND: {
        "severity": "info",
        "message": "Configuration file not found",
        "recovery": "Using default configuration; create ~/.reveng/config.yaml to customize",
    },
    ErrorCode.CONFIG_INVALID_FORMAT: {
        "severity": "error",
        "message": "Configuration file has invalid format",
        "recovery": "Fix YAML syntax errors or delete file to use defaults",
    },
    ErrorCode.NETWORK_CONNECTION_FAILED: {
        "severity": "error",
        "message": "Network connection failed",
        "recovery": "Check internet connectivity and proxy settings",
    },
    ErrorCode.NETWORK_DOWNLOAD_FAILED: {
        "severity": "error",
        "message": "File download failed",
        "recovery": "Retry the operation or download manually",
    },
    ErrorCode.NETWORK_CHECKSUM_MISMATCH: {
        "severity": "critical",
        "message": "Downloaded file checksum mismatch",
        "recovery": "Delete corrupted file and retry download",
    },
    ErrorCode.ML_MODEL_NOT_AVAILABLE: {
        "severity": "warning",
        "message": "ML model not available",
        "recovery": "Analysis will continue with heuristic-based approach",
    },
    ErrorCode.ML_INFERENCE_FAILED: {
        "severity": "warning",
        "message": "ML inference failed",
        "recovery": "Falling back to heuristic analysis",
    },
    ErrorCode.UNKNOWN_ERROR: {
        "severity": "error",
        "message": "An unknown error occurred",
        "recovery": "Check logs for details",
    },
}


class REVENGError(Exception):
    """Base exception for REVENG with structured error information"""

    def __init__(
        self,
        error_code: ErrorCode,
        message: str = None,
        details: Dict[str, Any] = None,
        recovery_hint: str = None,
    ):
        """
        Create a structured REVENG error

        Args:
            error_code: Standardized error code
            message: Optional custom error message (overrides default)
            details: Additional error context/details
            recovery_hint: Optional custom recovery suggestion (overrides default)
        """
        self.error_code = error_code
        self.details = details or {}

        # Get metadata
        metadata = ERROR_METADATA.get(error_code, {})
        self.severity = metadata.get("severity", "error")
        self.message = message or metadata.get("message", str(error_code.value))
        self.recovery = recovery_hint or metadata.get(
            "recovery", "Check logs for details"
        )

        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to structured dictionary for APIs"""
        return {
            "error_code": self.error_code.value,
            "severity": self.severity,
            "message": self.message,
            "recovery": self.recovery,
            "details": self.details,
        }

    def __str__(self) -> str:
        """Human-readable error string"""
        return f"[{self.error_code.value}] {self.message} (Recovery: {self.recovery})"
