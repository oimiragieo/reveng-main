# `claude.md` — `agent_sdk/skills`

**Repository path:** `src/reveng/agent_sdk/skills/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `builtin/` — [`claude.md`](builtin/claude.md)

## Python modules

### `__init__.py`
- **Summary:** REVENG Agent SDK - Skills System

### `base.py`
- **Summary:** Base Skill Classes
- **Classes:**
  - `SkillResult` — Result from skill execution
  - `BaseSkill` — Base class for agent skills.

### `loader.py`
- **Summary:** Skill Loader
- **Functions / coroutines:**
  - `def load_skills()` — Load all skills from directory.
  - `def load_skill_from_file()` — Load a skill from a Python file.
  - `def create_skill_template()` — Create a skill template file.
  - `def _to_class_name()` — Convert skill name to class name (e.g., my_skill -> MySkill)

### `registry.py`
- **Summary:** Skill Registry
- **Classes:**
  - `SkillRegistry` — Registry for agent skills.
- **Functions / coroutines:**
  - `def get_global_registry()` — Get the global skill registry

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
