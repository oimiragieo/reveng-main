"""
Claude SDK Client
=================

Main client for interacting with Claude API with enterprise features.
"""

import os
from typing import Any, AsyncIterator, Dict, List, Optional

from anthropic import AsyncAnthropic

from .cost_tracking import CostTracker
from .exceptions import ClientError, ToolError
from .permissions import PermissionManager
from .tools.registry import ToolRegistry
from .types import Message, MessageType, PermissionMode, TextBlock, UsageMetrics


class ClaudeSDKClient:
    """
    Enterprise Claude SDK Client.

    Provides:
    - Asynchronous streaming responses
    - Tool use with permission control
    - Cost tracking and analytics
    - Session management
    - Multi-turn conversations

    Example:
        ```python
        async with ClaudeSDKClient(
            api_key="your-api-key",
            allowed_tools=["analyze_binary", "deobfuscate_js"]
        ) as client:
            async for message in client.query("Analyze this binary"):
                print(message)
        ```
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4.5-20250929",
        max_tokens: int = 4096,
        allowed_tools: Optional[List[str]] = None,
        blocked_tools: Optional[List[str]] = None,
        permission_mode: PermissionMode = PermissionMode.ACCEPT_ALL,
        enable_cost_tracking: bool = True,
        session_id: Optional[str] = None,
    ):
        """
        Initialize Claude SDK Client.

        Args:
            api_key: Anthropic API key (or use ANTHROPIC_API_KEY env var)
            model: Model to use
            max_tokens: Maximum tokens in response
            allowed_tools: List of allowed tool names
            blocked_tools: List of blocked tool names
            permission_mode: Permission mode for tool execution
            enable_cost_tracking: Enable cost tracking
            session_id: Session identifier for cost tracking
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ClientError("API key required (set ANTHROPIC_API_KEY or pass api_key)")

        self.model = model
        self.max_tokens = max_tokens

        # Initialize Anthropic client
        self.client = AsyncAnthropic(api_key=self.api_key)

        # Initialize components
        self.tool_registry = ToolRegistry()
        self.permission_manager = PermissionManager(
            mode=permission_mode, allowed_tools=allowed_tools, blocked_tools=blocked_tools
        )

        # Cost tracking
        self.enable_cost_tracking = enable_cost_tracking
        self.session_id = session_id or f"session-{os.getpid()}"
        self.cost_tracker = CostTracker() if enable_cost_tracking else None

        # Conversation history
        self.messages: List[Message] = []

    async def query(
        self,
        prompt: str,
        system: Optional[str] = None,
        tools: Optional[List[str]] = None,
        max_iterations: int = 10,
    ) -> AsyncIterator[Message]:
        """
        Query Claude with streaming response.

        Args:
            prompt: User prompt
            system: System prompt
            tools: List of tool names to enable (None = all registered tools)
            max_iterations: Maximum tool use iterations

        Yields:
            Message objects with streaming content

        Example:
            ```python
            async for message in client.query("Analyze malware.exe"):
                if message.type == MessageType.TEXT:
                    print(message.get_text())
                elif message.type == MessageType.TOOL_USE:
                    print(f"Using tool: {message.get_tool_uses()[0].name}")
            ```
        """
        # Add user message to history
        user_message = Message(type=MessageType.USER, content=[TextBlock(text=prompt)])
        self.messages.append(user_message)

        # Get available tools
        available_tools = self._get_available_tools(tools)

        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            try:
                # Call Claude API
                response = await self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=system or "You are a helpful assistant.",
                    messages=[msg.to_anthropic_format() for msg in self.messages],
                    tools=(
                        [tool.to_anthropic_format() for tool in available_tools]
                        if available_tools
                        else None
                    ),
                )

                # Track usage
                if self.enable_cost_tracking and hasattr(response, "usage"):
                    usage = UsageMetrics(
                        input_tokens=response.usage.input_tokens,
                        output_tokens=response.usage.output_tokens,
                        cache_creation_tokens=getattr(
                            response.usage, "cache_creation_input_tokens", 0
                        ),
                        cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
                    )
                    self.cost_tracker.track_usage(self.session_id, usage, self.model)

                # Convert response to Message
                assistant_message = Message.from_anthropic_response(response)
                self.messages.append(assistant_message)

                # Yield the message
                yield assistant_message

                # Check if tool use is needed
                tool_uses = assistant_message.get_tool_uses()
                if not tool_uses:
                    break  # No more tool use, we're done

                # Execute tools
                tool_results = []
                for tool_use in tool_uses:
                    result = await self._execute_tool(tool_use.name, tool_use.input)
                    tool_results.append(result)

                # Add tool results to history
                tool_result_message = Message(type=MessageType.USER, content=tool_results)
                self.messages.append(tool_result_message)

            except Exception as e:
                raise ClientError(f"Error during query: {str(e)}")

    async def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute a tool with permission checks"""
        # Check permissions
        if not self.permission_manager.can_execute(tool_name):
            raise ToolError(f"Permission denied for tool: {tool_name}")

        # Get tool from registry
        tool = self.tool_registry.get(tool_name)
        if not tool:
            raise ToolError(f"Tool not found: {tool_name}")

        # Run pre-hooks
        if not await self.permission_manager.run_pre_hooks(tool_name, args):
            raise ToolError(f"Pre-hook blocked execution of tool: {tool_name}")

        # Execute tool
        result = await tool.safe_execute(args)

        # Track execution
        self.permission_manager.track_execution(tool_name)
        if self.enable_cost_tracking:
            self.cost_tracker.track_usage(
                self.session_id,
                UsageMetrics(),  # Tool execution doesn't consume tokens
                self.model,
                tool_name=tool_name,
            )

        # Run post-hooks
        await self.permission_manager.run_post_hooks(tool_name, result)

        return result

    def _get_available_tools(self, tool_names: Optional[List[str]]) -> List:
        """Get available tools based on permissions and tool_names filter"""
        if tool_names is None:
            # Get all registered tools
            all_tools = list(self.tool_registry.tools.values())
        else:
            # Get only specified tools
            all_tools = [
                self.tool_registry.get(name)
                for name in tool_names
                if self.tool_registry.get(name) is not None
            ]

        # Filter by permissions
        return [tool for tool in all_tools if self.permission_manager.can_execute(tool.name)]

    def register_tool(self, tool):
        """Register a tool with the client"""
        self.tool_registry.register(tool)

    def get_cost_report(self):
        """Get cost report for current session"""
        if not self.enable_cost_tracking:
            return None
        return self.cost_tracker.get_report(self.session_id)

    def clear_history(self):
        """Clear conversation history"""
        self.messages.clear()

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.client.close()
