"""
Exception classes for REVENG Agent SDK.

All custom exceptions inherit from AgentSDKError for easy catching.
"""


class AgentSDKError(Exception):
    """Base exception for all agent SDK errors."""

    pass


class ClientError(AgentSDKError):
    """Error in SDK client operations."""

    pass


class ToolError(AgentSDKError):
    """Error during tool execution."""

    def __init__(self, tool_name: str, message: str, original_error: Exception = None):
        self.tool_name = tool_name
        self.original_error = original_error
        super().__init__(f"Tool '{tool_name}' error: {message}")


class SessionError(AgentSDKError):
    """Error in session management."""

    pass


class PermissionError(AgentSDKError):
    """Permission denied for tool/operation."""

    def __init__(self, tool_name: str, reason: str = ""):
        self.tool_name = tool_name
        super().__init__(
            f"Permission denied for tool '{tool_name}'"
            + (f": {reason}" if reason else "")
        )


class ValidationError(AgentSDKError):
    """Input validation error."""

    pass


class ConfigurationError(AgentSDKError):
    """Configuration error."""

    pass


class TimeoutError(AgentSDKError):
    """Operation timeout."""

    pass


class RateLimitError(AgentSDKError):
    """API rate limit exceeded."""

    pass
