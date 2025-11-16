"""
Hook Manager

Manages function hooks, interceptors, and callbacks for dynamic instrumentation.
"""

import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
import time


class HookType(Enum):
    """Types of hooks"""
    ENTRY = "entry"           # Hook function entry point
    EXIT = "exit"             # Hook function exit point
    REPLACE = "replace"       # Replace entire function
    INLINE = "inline"         # Inline hook at specific offset


@dataclass
class Hook:
    """Hook configuration"""
    name: str
    address: int
    hook_type: HookType
    callback: Callable
    enabled: bool = True
    hit_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HookEvent:
    """Event data from hook execution"""
    hook_name: str
    function_name: str
    args: List[Any]
    return_value: Any = None
    timestamp: float = field(default_factory=time.time)
    thread_id: int = 0
    backtrace: Optional[List[str]] = None
    modified: bool = False


class HookManager:
    """
    Manages function hooks and interception callbacks.

    Example:
        >>> manager = HookManager()
        >>> manager.add_hook("malloc", 0x12345, HookType.ENTRY, on_malloc)
        >>> manager.enable_all()
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hooks: Dict[str, Hook] = {}
        self.events: List[HookEvent] = []
        self.global_enabled = True

    def add_hook(self, name: str, address: int, hook_type: HookType,
                 callback: Callable, metadata: Optional[Dict] = None) -> bool:
        """
        Add a new hook.

        Args:
            name: Hook identifier
            address: Target address
            hook_type: Type of hook
            callback: Callback function
            metadata: Optional metadata

        Returns:
            True if added successfully
        """
        if name in self.hooks:
            self.logger.warning(f"Hook '{name}' already exists")
            return False

        hook = Hook(
            name=name,
            address=address,
            hook_type=hook_type,
            callback=callback,
            metadata=metadata or {}
        )

        self.hooks[name] = hook
        self.logger.info(f"Added hook: {name} @ 0x{address:x}")
        return True

    def remove_hook(self, name: str) -> bool:
        """Remove a hook by name"""
        if name not in self.hooks:
            return False

        del self.hooks[name]
        self.logger.info(f"Removed hook: {name}")
        return True

    def enable_hook(self, name: str) -> bool:
        """Enable a specific hook"""
        if name not in self.hooks:
            return False

        self.hooks[name].enabled = True
        return True

    def disable_hook(self, name: str) -> bool:
        """Disable a specific hook"""
        if name not in self.hooks:
            return False

        self.hooks[name].enabled = False
        return True

    def enable_all(self):
        """Enable all hooks"""
        for hook in self.hooks.values():
            hook.enabled = True
        self.global_enabled = True

    def disable_all(self):
        """Disable all hooks"""
        for hook in self.hooks.values():
            hook.enabled = False
        self.global_enabled = False

    def trigger_hook(self, name: str, *args, **kwargs) -> Any:
        """
        Manually trigger a hook callback.

        Args:
            name: Hook name
            *args: Arguments to pass to callback
            **kwargs: Keyword arguments

        Returns:
            Callback return value
        """
        if name not in self.hooks:
            return None

        hook = self.hooks[name]

        if not hook.enabled or not self.global_enabled:
            return None

        hook.hit_count += 1

        try:
            result = hook.callback(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Hook callback error: {e}")
            return None

    def record_event(self, event: HookEvent):
        """Record a hook event"""
        self.events.append(event)

    def get_events(self, hook_name: Optional[str] = None,
                   limit: Optional[int] = None) -> List[HookEvent]:
        """
        Get recorded hook events.

        Args:
            hook_name: Filter by hook name
            limit: Maximum events to return

        Returns:
            List of hook events
        """
        events = self.events

        if hook_name:
            events = [e for e in events if e.hook_name == hook_name]

        if limit:
            events = events[-limit:]

        return events

    def get_statistics(self) -> Dict[str, Any]:
        """Get hook statistics"""
        return {
            'total_hooks': len(self.hooks),
            'enabled_hooks': sum(1 for h in self.hooks.values() if h.enabled),
            'total_events': len(self.events),
            'hook_stats': {
                name: {
                    'hit_count': hook.hit_count,
                    'enabled': hook.enabled,
                    'type': hook.hook_type.value
                }
                for name, hook in self.hooks.items()
            }
        }

    def clear_events(self):
        """Clear all recorded events"""
        self.events.clear()

    def clear_all(self):
        """Clear all hooks and events"""
        self.hooks.clear()
        self.events.clear()
