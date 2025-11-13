"""
REVENG Agent SDK - Skills System
=================================

Skills are reusable agent capabilities that can be loaded from .claude/skills/

Features:
- Skill discovery and loading
- Skill templates
- Skill composition
- Built-in security and analysis skills

Example:
    ```python
    from reveng.agent_sdk.skills import SkillRegistry, load_skills

    # Load all skills from .claude/skills/
    registry = load_skills()

    # Get a skill
    skill = registry.get("security_audit")

    # Execute skill
    result = await skill.execute({"target": "malware.exe"})
    ```
"""

from .base import BaseSkill, SkillResult
from .loader import load_skill_from_file, load_skills
from .registry import SkillRegistry

__all__ = [
    "BaseSkill",
    "SkillResult",
    "SkillRegistry",
    "load_skills",
    "load_skill_from_file",
]
