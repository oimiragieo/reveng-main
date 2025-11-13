"""
Skill Registry
==============

Registry for managing and discovering skills.
"""

from typing import Dict, List, Optional

from .base import BaseSkill


class SkillRegistry:
    """
    Registry for agent skills.

    Manages skill discovery, loading, and execution.

    Example:
        ```python
        registry = SkillRegistry()

        # Register a skill
        registry.register(SecurityAuditSkill())

        # Get a skill
        skill = registry.get("security_audit")

        # List all skills
        skills = registry.list_skills()
        ```
    """

    def __init__(self):
        self.skills: Dict[str, BaseSkill] = {}

    def register(self, skill: BaseSkill):
        """Register a skill"""
        if not skill.name:
            raise ValueError("Skill must have a name")

        self.skills[skill.name] = skill

    def unregister(self, name: str):
        """Unregister a skill"""
        if name in self.skills:
            del self.skills[name]

    def get(self, name: str) -> Optional[BaseSkill]:
        """Get a skill by name"""
        return self.skills.get(name)

    def has(self, name: str) -> bool:
        """Check if skill is registered"""
        return name in self.skills

    def list_skills(self) -> List[Dict[str, str]]:
        """List all registered skills"""
        return [skill.get_info() for skill in self.skills.values()]

    def find_by_tag(self, tag: str) -> List[BaseSkill]:
        """Find skills by tag"""
        return [skill for skill in self.skills.values() if tag in skill.tags]

    def clear(self):
        """Clear all skills"""
        self.skills.clear()

    def __len__(self) -> int:
        """Get number of registered skills"""
        return len(self.skills)

    def __iter__(self):
        """Iterate over skills"""
        return iter(self.skills.values())


# Global skill registry
_global_registry = SkillRegistry()


def get_global_registry() -> SkillRegistry:
    """Get the global skill registry"""
    return _global_registry
