"""
Type definitions for REVENG Agent SDK.

This module provides all type definitions, enums, and data classes
used throughout the agent SDK.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from datetime import datetime


class MessageType(Enum):
    """Types of messages in agent conversations."""

    TEXT = "text"
    THINKING = "thinking"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    RESULT = "result"
    ERROR = "error"


class PermissionMode(Enum):
    """Permission modes for tool execution."""

    PLAN = "plan"  # Ask before executing
    ACCEPT_EDITS = "acceptEdits"  # Auto-accept file edits
    ACCEPT_ALL = "acceptAll"  # Auto-accept all tools
    DENY_ALL = "denyAll"  # Deny all tool use


@dataclass
class TextBlock:
    """A text content block."""

    type: str = "text"
    text: str = ""


@dataclass
class ThinkingBlock:
    """A thinking/reasoning content block."""

    type: str = "thinking"
    thinking: str = ""


@dataclass
class ToolUseBlock:
    """A tool use request block."""

    type: str = "tool_use"
    id: str = ""
    name: str = ""
    input: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResultBlock:
    """A tool execution result block."""

    type: str = "tool_result"
    tool_use_id: str = ""
    content: Union[str, List[Dict[str, Any]]] = ""
    is_error: bool = False


@dataclass
class Message:
    """A message in an agent conversation."""

    type: MessageType
    content: List[Union[TextBlock, ThinkingBlock, ToolUseBlock, ToolResultBlock]]
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_text(self) -> str:
        """Extract all text content from message."""
        texts = []
        for block in self.content:
            if isinstance(block, TextBlock):
                texts.append(block.text)
            elif isinstance(block, ThinkingBlock):
                texts.append(f"[Thinking: {block.thinking}]")
        return "\n".join(texts)

    def get_tool_uses(self) -> List[ToolUseBlock]:
        """Extract all tool use blocks."""
        return [block for block in self.content if isinstance(block, ToolUseBlock)]

    def get_tool_results(self) -> List[ToolResultBlock]:
        """Extract all tool result blocks."""
        return [block for block in self.content if isinstance(block, ToolResultBlock)]


@dataclass
class UsageMetrics:
    """Token usage metrics for cost tracking."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0

    def total_tokens(self) -> int:
        """Calculate total tokens used."""
        return (
            self.input_tokens +
            self.output_tokens +
            self.cache_creation_tokens +
            self.cache_read_tokens
        )


@dataclass
class CostReport:
    """Cost tracking report for a session."""

    session_id: str
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_tokens: int = 0
    steps: int = 0
    tool_calls: int = 0
    duration_seconds: float = 0.0
    model: str = "claude-sonnet-4-5"

    def add_usage(self, usage: UsageMetrics, model_pricing: Optional[Dict[str, float]] = None):
        """Add usage metrics and calculate cost."""
        # Default pricing for Claude Sonnet 4.5 (per 1M tokens)
        if model_pricing is None:
            model_pricing = {
                "input": 3.00,  # $3 per 1M input tokens
                "output": 15.00,  # $15 per 1M output tokens
                "cache_write": 3.75,  # $3.75 per 1M cache write
                "cache_read": 0.30,  # $0.30 per 1M cache read
            }

        # Calculate cost
        input_cost = (usage.input_tokens / 1_000_000) * model_pricing["input"]
        output_cost = (usage.output_tokens / 1_000_000) * model_pricing["output"]
        cache_write_cost = (usage.cache_creation_tokens / 1_000_000) * model_pricing["cache_write"]
        cache_read_cost = (usage.cache_read_tokens / 1_000_000) * model_pricing["cache_read"]

        step_cost = input_cost + output_cost + cache_write_cost + cache_read_cost

        # Update totals
        self.total_cost_usd += step_cost
        self.total_tokens += usage.total_tokens()
        self.input_tokens += usage.input_tokens
        self.output_tokens += usage.output_tokens
        self.cache_tokens += usage.cache_creation_tokens + usage.cache_read_tokens
        self.steps += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "total_tokens": self.total_tokens,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_tokens": self.cache_tokens,
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "duration_seconds": round(self.duration_seconds, 2),
            "model": self.model,
            "cost_per_step": round(self.total_cost_usd / max(self.steps, 1), 4),
            "tokens_per_step": self.total_tokens // max(self.steps, 1),
        }


@dataclass
class ToolDefinition:
    """Definition of a tool for Claude."""

    name: str
    description: str
    input_schema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
