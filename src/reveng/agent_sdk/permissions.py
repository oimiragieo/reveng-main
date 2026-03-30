"""
Permissions and Security System
================================

Control tool access, implement hooks, and enforce security policies.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Set

from .types import PermissionMode

logger = logging.getLogger(__name__)


@dataclass
class ToolPermission:
    """Permission configuration for a tool"""

    allowed: bool = True
    require_approval: bool = False
    max_executions: Optional[int] = None
    execution_count: int = 0

    def can_execute(self) -> bool:
        """Check if tool can be executed"""
        if not self.allowed:
            return False

        if self.max_executions is not None:
            return self.execution_count < self.max_executions

        return True

    def increment_execution(self):
        """Increment execution counter"""
        self.execution_count += 1


class PermissionManager:
    """
    Manage tool permissions and security policies.

    Example:
        ```python
        manager = PermissionManager(mode=PermissionMode.PLAN)

        # Allow specific tools
        manager.allow_tools(["read_file", "analyze_binary"])

        # Block dangerous tools
        manager.block_tools(["execute_code", "write_file"])

        # Check permission
        if manager.can_execute("read_file"):
            # Execute tool
            pass
        ```
    """

    def __init__(
        self,
        mode: PermissionMode = PermissionMode.PLAN,
        allowed_tools: Optional[List[str]] = None,
        blocked_tools: Optional[List[str]] = None,
    ):
        """
        Initialize permission manager.

        Args:
            mode: Permission mode (plan, acceptEdits, acceptAll)
            allowed_tools: Allowlist of tool names
            blocked_tools: Blocklist of tool names
        """
        self.mode = mode
        self.allowed_tools: Set[str] = set(allowed_tools or [])
        self.blocked_tools: Set[str] = set(blocked_tools or [])
        self.tool_permissions: Dict[str, ToolPermission] = {}

        # Hooks
        self.pre_tool_hooks: List[Callable] = []
        self.post_tool_hooks: List[Callable] = []

    def can_execute(self, tool_name: str) -> bool:
        """
        Check if a tool can be executed.

        Args:
            tool_name: Name of the tool

        Returns:
            True if tool can be executed
        """
        # Check blocklist first
        if tool_name in self.blocked_tools:
            logger.warning(f"Tool '{tool_name}' is blocked")
            return False

        # If allowlist is set, check it
        if self.allowed_tools and tool_name not in self.allowed_tools:
            logger.warning(f"Tool '{tool_name}' not in allowlist")
            return False

        # Check tool-specific permissions
        if tool_name in self.tool_permissions:
            permission = self.tool_permissions[tool_name]
            if not permission.can_execute():
                logger.warning(f"Tool '{tool_name}' permission denied")
                return False

        # Check mode
        if self.mode == PermissionMode.PLAN:
            # In plan mode, only allow read-only operations
            read_only_tools = {"read_file", "list_directory", "search_files", "analyze_binary"}
            return tool_name in read_only_tools

        elif self.mode == PermissionMode.ACCEPT_EDITS:
            # Allow edits but require approval for execution
            dangerous_tools = {"execute_code", "bash", "write_file"}
            if tool_name in dangerous_tools:
                return self._request_approval(tool_name)

        # ACCEPT_ALL mode allows everything (that's not blocked)
        return True

    def allow_tools(self, tool_names: List[str]):
        """Add tools to allowlist"""
        self.allowed_tools.update(tool_names)

    def block_tools(self, tool_names: List[str]):
        """Add tools to blocklist"""
        self.blocked_tools.update(tool_names)

    def set_tool_permission(self, tool_name: str, permission: ToolPermission):
        """Set custom permission for a tool"""
        self.tool_permissions[tool_name] = permission

    def limit_executions(self, tool_name: str, max_executions: int):
        """Limit number of executions for a tool"""
        if tool_name not in self.tool_permissions:
            self.tool_permissions[tool_name] = ToolPermission()

        self.tool_permissions[tool_name].max_executions = max_executions

    def track_execution(self, tool_name: str):
        """Track tool execution"""
        if tool_name in self.tool_permissions:
            self.tool_permissions[tool_name].increment_execution()

    def register_pre_hook(self, hook: Callable):
        """
        Register a pre-tool-execution hook.

        Args:
            hook: Callable that receives (tool_name, args) and returns bool
        """
        self.pre_tool_hooks.append(hook)

    def register_post_hook(self, hook: Callable):
        """
        Register a post-tool-execution hook.

        Args:
            hook: Callable that receives (tool_name, result)
        """
        self.post_tool_hooks.append(hook)

    async def run_pre_hooks(self, tool_name: str, args: Dict[str, Any]) -> bool:
        """
        Run pre-execution hooks.

        Returns:
            True if execution should proceed
        """
        for hook in self.pre_tool_hooks:
            try:
                result = hook(tool_name, args)
                if asyncio.iscoroutine(result):
                    result = await result

                if not result:
                    logger.info(f"Pre-hook blocked execution of {tool_name}")
                    return False

            except Exception as e:
                logger.error(f"Error in pre-hook: {e}")
                return False

        return True

    async def run_post_hooks(self, tool_name: str, result: Any):
        """Run post-execution hooks"""
        for hook in self.post_tool_hooks:
            try:
                hook_result = hook(tool_name, result)
                if asyncio.iscoroutine(hook_result):
                    await hook_result

            except Exception as e:
                logger.error(f"Error in post-hook: {e}")

    def _request_approval(self, tool_name: str) -> bool:
        """Request user approval for tool execution (simplified)"""
        # In a real implementation, this would prompt the user
        # For now, we'll just log and deny
        logger.warning(f"Tool '{tool_name}' requires approval (not implemented)")
        return False

    def get_permissions_summary(self) -> Dict[str, Any]:
        """Get summary of current permissions"""
        return {
            "mode": self.mode.value,
            "allowed_tools": list(self.allowed_tools),
            "blocked_tools": list(self.blocked_tools),
            "tool_permissions": {
                name: {
                    "allowed": perm.allowed,
                    "require_approval": perm.require_approval,
                    "max_executions": perm.max_executions,
                    "execution_count": perm.execution_count,
                }
                for name, perm in self.tool_permissions.items()
            },
        }


# Global permission manager
_global_manager: Optional[PermissionManager] = None


def get_global_manager() -> PermissionManager:
    """Get the global permission manager"""
    global _global_manager
    if _global_manager is None:
        _global_manager = PermissionManager()
    return _global_manager
