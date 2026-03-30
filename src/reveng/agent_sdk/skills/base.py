"""
Base Skill Classes
==================

Base classes for creating reusable agent skills.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SkillResult:
    """Result from skill execution"""

    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success_result(
        cls, output: Any, metadata: Optional[Dict[str, Any]] = None
    ) -> "SkillResult":
        """Create a success result"""
        return cls(success=True, output=output, metadata=metadata or {})

    @classmethod
    def error_result(cls, error: str, metadata: Optional[Dict[str, Any]] = None) -> "SkillResult":
        """Create an error result"""
        return cls(success=False, output=None, error=error, metadata=metadata or {})


class BaseSkill(ABC):
    """
    Base class for agent skills.

    Skills are high-level capabilities that combine multiple tools
    and operations to accomplish complex tasks.

    Example:
        ```python
        class SecurityAuditSkill(BaseSkill):
            name = "security_audit"
            description = "Comprehensive security audit"

            async def execute(self, args: Dict[str, Any]) -> SkillResult:
                binary_path = args["binary_path"]

                # Use multiple tools
                binary_analysis = await self.analyze_binary(binary_path)
                malware_scan = await self.scan_malware(binary_path)
                vuln_check = await self.check_vulnerabilities(binary_path)

                # Combine results
                return SkillResult.success_result({
                    "binary_analysis": binary_analysis,
                    "malware_scan": malware_scan,
                    "vulnerabilities": vuln_check
                })
        ```
    """

    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    tags: List[str] = []

    # Skill configuration
    config: Dict[str, Any] = {}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize skill with optional configuration"""
        self.config = config or {}

    @abstractmethod
    async def execute(self, args: Dict[str, Any]) -> SkillResult:
        """
        Execute the skill.

        Args:
            args: Skill-specific arguments

        Returns:
            SkillResult with output or error
        """
        pass

    async def safe_execute(self, args: Dict[str, Any]) -> SkillResult:
        """Execute skill with error handling and timing"""
        start_time = time.time()

        try:
            # Validate arguments if schema is defined
            if hasattr(self, "input_schema"):
                self._validate_args(args)

            # Execute skill
            result = await self.execute(args)

            # Add execution time
            result.execution_time = time.time() - start_time

            return result

        except Exception as e:
            return SkillResult(
                success=False, output=None, error=str(e), execution_time=time.time() - start_time
            )

    def _validate_args(self, args: Dict[str, Any]):
        """Validate arguments against input schema"""
        if not hasattr(self, "input_schema"):
            return

        schema = self.input_schema
        required = schema.get("required", [])

        # Check required fields
        for field_name in required:
            if field_name not in args:
                raise ValueError(f"Missing required argument: {field_name}")

    def get_info(self) -> Dict[str, Any]:
        """Get skill information"""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "tags": self.tags,
        }
