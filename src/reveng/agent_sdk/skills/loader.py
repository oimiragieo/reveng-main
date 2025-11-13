"""
Skill Loader
============

Load skills from .claude/skills/ directory and Python modules.
"""

import importlib.util
import os
from pathlib import Path
from typing import Optional

from .base import BaseSkill
from .registry import SkillRegistry, get_global_registry


def load_skills(
    skills_dir: Optional[str] = None, registry: Optional[SkillRegistry] = None
) -> SkillRegistry:
    """
    Load all skills from directory.

    Args:
        skills_dir: Directory containing skills (default: .claude/skills/)
        registry: SkillRegistry to use (default: global registry)

    Returns:
        SkillRegistry with loaded skills

    Example:
        ```python
        # Load from default directory
        registry = load_skills()

        # Load from custom directory
        registry = load_skills("./my_skills")
        ```
    """
    if registry is None:
        registry = get_global_registry()

    if skills_dir is None:
        # Search for .claude/skills/ directory
        search_paths = [
            Path(".claude/skills"),
            Path.home() / ".claude" / "skills",
            Path.home() / ".config" / "claude" / "skills",
        ]

        for path in search_paths:
            if path.exists():
                skills_dir = str(path)
                break

    # If no directory found, return empty registry
    if skills_dir is None or not Path(skills_dir).exists():
        return registry

    # Load all Python files in skills directory
    skills_path = Path(skills_dir)
    for skill_file in skills_path.glob("*.py"):
        if skill_file.name.startswith("_"):
            continue

        try:
            skill = load_skill_from_file(str(skill_file))
            if skill:
                registry.register(skill)
        except Exception as e:
            print(f"Warning: Failed to load skill from {skill_file}: {e}")

    return registry


def load_skill_from_file(file_path: str) -> Optional[BaseSkill]:
    """
    Load a skill from a Python file.

    The file should define a class that inherits from BaseSkill.

    Args:
        file_path: Path to Python file containing skill

    Returns:
        BaseSkill instance or None

    Example:
        ```python
        skill = load_skill_from_file("./my_skill.py")
        if skill:
            result = await skill.execute({"arg": "value"})
        ```
    """
    # Load module from file
    spec = importlib.util.spec_from_file_location("skill_module", file_path)
    if spec is None or spec.loader is None:
        return None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Find BaseSkill subclass in module
    for item_name in dir(module):
        item = getattr(module, item_name)

        # Check if it's a BaseSkill subclass (but not BaseSkill itself)
        if isinstance(item, type) and issubclass(item, BaseSkill) and item is not BaseSkill:

            # Instantiate and return
            return item()

    return None


def create_skill_template(name: str, output_path: str):
    """
    Create a skill template file.

    Args:
        name: Name of the skill
        output_path: Where to save the template

    Example:
        ```python
        create_skill_template("my_skill", ".claude/skills/my_skill.py")
        ```
    """
    template = f'''"""
{name} Skill
{"=" * (len(name) + 6)}

Description of your skill.
"""

from reveng.agent_sdk.skills import BaseSkill, SkillResult
from typing import Any, Dict


class {_to_class_name(name)}(BaseSkill):
    """Your skill description"""

    name = "{name}"
    description = "Description of your skill"
    version = "1.0.0"
    author = "Your Name"
    tags = ["tag1", "tag2"]

    # Define input schema (optional)
    input_schema = {{
        "type": "object",
        "properties": {{
            "arg1": {{
                "type": "string",
                "description": "Description of arg1"
            }}
        }},
        "required": ["arg1"]
    }}

    async def execute(self, args: Dict[str, Any]) -> SkillResult:
        """
        Execute the skill.

        Args:
            args: Skill arguments (validated against input_schema)

        Returns:
            SkillResult with output or error
        """
        try:
            # Your skill logic here
            arg1 = args["arg1"]

            # Do something...
            result = f"Processed: {{arg1}}"

            return SkillResult.success_result({{
                "message": result
            }})

        except Exception as e:
            return SkillResult.error_result(str(e))
'''

    # Create parent directory if needed
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Write template
    with open(output_path, "w") as f:
        f.write(template)


def _to_class_name(name: str) -> str:
    """Convert skill name to class name (e.g., my_skill -> MySkill)"""
    return "".join(word.capitalize() for word in name.split("_"))
