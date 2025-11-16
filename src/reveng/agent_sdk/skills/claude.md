# Agent SDK - Skills System

## Overview

The Skills System provides high-level, reusable agent capabilities that combine multiple tools and operations to accomplish complex reverse engineering tasks. Skills are discoverable, composable, and can be loaded dynamically from `.claude/skills/` directories.

Unlike tools (which are atomic operations), skills orchestrate multiple tools and implement sophisticated workflows for tasks like security audits, vulnerability discovery, and code analysis.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/skills/`

## Files in This Directory

### `__init__.py` (39 lines)
Public API for the skills system.

**Exports:**
- `BaseSkill` - Base class for all skills
- `SkillResult` - Skill execution result container
- `SkillRegistry` - Registry for skill discovery and management
- `load_skills` - Load all skills from `.claude/skills/`
- `load_skill_from_file` - Load a single skill from file

### `base.py` (137 lines)
Base classes for creating agent skills.

**Key Classes:**

**SkillResult:**
```python
@dataclass
class SkillResult:
    success: bool
    output: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
```

Factory methods:
- `SkillResult.success_result(output, metadata)` - Create success result
- `SkillResult.error_result(error, metadata)` - Create error result

**BaseSkill:**
```python
class BaseSkill(ABC):
    name: str = ""
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    tags: List[str] = []
    config: Dict[str, Any] = {}

    async def execute(self, args: Dict[str, Any]) -> SkillResult:
        # Implement skill logic
        pass

    async def safe_execute(self, args: Dict[str, Any]) -> SkillResult:
        # Execute with error handling and timing
        pass
```

### `loader.py` (4957 lines)
Dynamic skill loading from files and directories.

**Key Functions:**
- `load_skills(directory=".claude/skills/")` - Load all skills from directory
- `load_skill_from_file(file_path)` - Load single skill from Python file
- `discover_skills(paths)` - Discover skills in multiple locations

**Features:**
- Automatic skill discovery
- Hot reloading support
- Dependency resolution
- Version compatibility checking
- Error handling and validation

**Example:**
```python
# Load all skills from default location
registry = load_skills()

# Load from custom directory
registry = load_skills("/path/to/skills/")

# Load single skill
skill = load_skill_from_file("my_skill.py")
```

### `registry.py` (2014 lines)
Central registry for skill management.

**Key Classes:**

**SkillRegistry:**
```python
class SkillRegistry:
    def register(self, skill: BaseSkill) -> None
    def get(self, name: str) -> Optional[BaseSkill]
    def list_skills(self) -> List[str]
    def get_info(self, name: str) -> Dict[str, Any]
    def search_by_tag(self, tag: str) -> List[BaseSkill]
```

**Features:**
- Skill registration and lookup
- Tag-based search
- Metadata retrieval
- Duplicate detection
- Thread-safe operations

## Architecture

### Skills vs Tools

```
┌─────────────────────────────────────┐
│            Skills                    │
│  - High-level workflows              │
│  - Multi-tool orchestration          │
│  - Complex logic                     │
│  - Reusable patterns                 │
└──────────────┬──────────────────────┘
               │
               ↓
┌─────────────────────────────────────┐
│            Tools                     │
│  - Atomic operations                 │
│  - Single responsibility             │
│  - Direct REVENG integration         │
└─────────────────────────────────────┘
```

### Skill Execution Flow

```
1. Agent Request
   ↓
2. SkillRegistry.get(skill_name)
   ↓
3. skill.safe_execute(args)
   ├─> Validate arguments
   ├─> Start timer
   ├─> skill.execute(args)
   │   ├─> Use Tool 1
   │   ├─> Use Tool 2
   │   ├─> Combine results
   │   └─> Return SkillResult
   ├─> Stop timer
   └─> Return with timing
   ↓
4. Return to Agent
```

### Skill Composition

```
SecurityAuditSkill
  ├─> BinaryAnalysisTool
  ├─> VulnerabilityDiscoverySkill
  │   ├─> PatternMatchingTool
  │   └─> HeuristicAnalysisTool
  ├─> MalwareDetectionTool
  └─> ReportGenerationSkill
```

## Key Concepts

### 1. Skill Definition

Skills extend BaseSkill and implement execute():

```python
from reveng.agent_sdk.skills import BaseSkill, SkillResult

class MySkill(BaseSkill):
    name = "my_skill"
    description = "Does something useful"
    version = "1.0.0"
    author = "Your Name"
    tags = ["analysis", "security"]

    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string"}
        },
        "required": ["target"]
    }

    async def execute(self, args):
        # Skill logic here
        result = await self.perform_work(args["target"])
        return SkillResult.success_result(result)
```

### 2. Skill Configuration

Skills can accept configuration:

```python
skill = MySkill(config={
    "timeout": 300,
    "verbose": True,
    "use_ml": True
})

result = await skill.execute({"target": "/path/to/binary"})
```

### 3. Error Handling

Skills use SkillResult for consistent error reporting:

```python
try:
    result = perform_analysis()
    return SkillResult.success_result(result)
except Exception as e:
    return SkillResult.error_result(f"Analysis failed: {str(e)}")
```

### 4. Metadata

Skills can attach metadata to results:

```python
return SkillResult.success_result(
    output=analysis_results,
    metadata={
        "tool_versions": {"analyzer": "1.0.0"},
        "analysis_time": 45.2,
        "confidence": 0.95
    }
)
```

## Usage Examples

### Example 1: Using a Built-in Skill

```python
from reveng.agent_sdk.skills import load_skills

# Load all skills
registry = load_skills()

# Get vulnerability discovery skill
vuln_skill = registry.get("vulnerability_discovery")

# Execute skill
result = await vuln_skill.execute({
    "target": "/path/to/binary.exe",
    "type": "binary",
    "depth": "deep"
})

if result.success:
    print(f"Found {result.output['vulnerabilities_found']} vulnerabilities")
    for vuln in result.output['vulnerabilities']:
        print(f"  - {vuln['type']}: {vuln['description']}")
else:
    print(f"Error: {result.error}")
```

### Example 2: Creating a Custom Skill

```python
from reveng.agent_sdk.skills import BaseSkill, SkillResult
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool, JSDeobfuscationTool

class ComprehensiveAuditSkill(BaseSkill):
    name = "comprehensive_audit"
    description = "Complete security audit of binary and scripts"
    version = "1.0.0"
    tags = ["audit", "security", "complete"]

    async def execute(self, args):
        binary_path = args["binary_path"]
        results = {}

        # Step 1: Binary analysis
        binary_tool = BinaryAnalysisTool()
        binary_result = await binary_tool.execute({"path": binary_path})
        results["binary_analysis"] = binary_result

        # Step 2: Extract and analyze scripts
        scripts = self.extract_scripts(binary_result)
        script_results = []

        for script in scripts:
            js_tool = JSDeobfuscationTool()
            script_result = await js_tool.execute({
                "code": script,
                "detect_malware": True
            })
            script_results.append(script_result)

        results["script_analysis"] = script_results

        # Step 3: Vulnerability discovery
        vuln_skill = VulnerabilityDiscoverySkill()
        vuln_result = await vuln_skill.execute({
            "target": binary_path,
            "type": "binary",
            "depth": "deep"
        })
        results["vulnerabilities"] = vuln_result.output

        # Step 4: Generate report
        report = self.generate_report(results)

        return SkillResult.success_result(
            output=report,
            metadata={"total_execution_time": 120.5}
        )

    def extract_scripts(self, binary_result):
        # Extract embedded scripts from binary
        return []

    def generate_report(self, results):
        # Generate comprehensive report
        return {"summary": "Audit complete", "results": results}
```

### Example 3: Skill with Configuration

```python
from reveng.agent_sdk.skills import BaseSkill, SkillResult

class ConfigurableAnalysisSkill(BaseSkill):
    name = "configurable_analysis"
    description = "Analysis with configurable options"

    def __init__(self, config=None):
        super().__init__(config)

        # Use configuration
        self.timeout = self.config.get("timeout", 60)
        self.verbose = self.config.get("verbose", False)
        self.use_ml = self.config.get("use_ml", True)

    async def execute(self, args):
        if self.verbose:
            print(f"Analyzing with timeout={self.timeout}s, ML={self.use_ml}")

        # Perform analysis with configuration
        # ...

        return SkillResult.success_result({"status": "complete"})

# Use with configuration
skill = ConfigurableAnalysisSkill(config={
    "timeout": 120,
    "verbose": True,
    "use_ml": False
})

result = await skill.execute({"target": "file.exe"})
```

### Example 4: Skill Registry Operations

```python
from reveng.agent_sdk.skills import SkillRegistry, load_skills

# Load all skills
registry = load_skills()

# List all available skills
skills = registry.list_skills()
print(f"Available skills: {skills}")

# Get skill information
info = registry.get_info("vulnerability_discovery")
print(f"Name: {info['name']}")
print(f"Description: {info['description']}")
print(f"Version: {info['version']}")
print(f"Tags: {info['tags']}")

# Search by tag
security_skills = registry.search_by_tag("security")
print(f"Security skills: {[s.name for s in security_skills]}")

# Register custom skill
my_skill = MyCustomSkill()
registry.register(my_skill)
```

## Configuration

### Skill Discovery Paths

Skills are discovered in these locations (in order):

1. `.claude/skills/` - Project-specific skills
2. `~/.claude/skills/` - User-global skills
3. `/usr/share/reveng/skills/` - System-wide skills
4. Built-in skills from `reveng.agent_sdk.skills.builtin`

### Loading Configuration

```python
# Load from default locations
registry = load_skills()

# Load from custom directory
registry = load_skills(directory="/custom/skills/")

# Load with specific paths
registry = load_skills()
```

## Testing

### Testing Skills

```python
import pytest
from reveng.agent_sdk.skills.builtin import VulnerabilityDiscoverySkill

@pytest.mark.asyncio
async def test_vulnerability_discovery():
    skill = VulnerabilityDiscoverySkill()

    result = await skill.execute({
        "target": "test.exe",
        "type": "binary",
        "depth": "quick"
    })

    assert result.success
    assert "vulnerabilities_found" in result.output
    assert result.execution_time > 0

@pytest.mark.asyncio
async def test_skill_error_handling():
    skill = VulnerabilityDiscoverySkill()

    result = await skill.execute({
        "target": "/nonexistent/file",
        "type": "binary"
    })

    # Should handle gracefully
    assert not result.success
    assert result.error is not None
```

### Running Tests

```bash
# Test all skills
pytest tests/agent_sdk/skills/

# Test specific skill
pytest tests/agent_sdk/skills/test_vulnerability_discovery.py

# Test with coverage
pytest --cov=reveng.agent_sdk.skills tests/agent_sdk/skills/
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/` - Parent SDK
- `/home/user/reveng-main/src/reveng/agent_sdk/skills/builtin/` - Built-in skills
- `/home/user/reveng-main/src/reveng/agent_sdk/tools/` - Tools used by skills

### External REVENG Integration
- Skills use all REVENG modules through tools:
  - `/home/user/reveng-main/src/reveng/analyzer/`
  - `/home/user/reveng-main/src/reveng/javascript/`
  - `/home/user/reveng-main/src/reveng/exploits/`
  - `/home/user/reveng-main/src/reveng/security/`

## Notes

### Design Philosophy

1. **Composition over Inheritance** - Skills compose tools rather than extending them
2. **Reusability** - Skills should be reusable across different projects
3. **Discoverability** - Skills are auto-discovered from standard locations
4. **Configurability** - Skills accept configuration for flexibility
5. **Error Resilience** - Skills handle errors gracefully

### Best Practices

1. **Keep skills focused** - One skill = one high-level task
2. **Use clear naming** - Skill names should describe what they do
3. **Provide rich metadata** - Include tags, version, author info
4. **Document thoroughly** - Clear description and input schema
5. **Handle errors** - Always return SkillResult, never raise unhandled exceptions
6. **Test extensively** - Unit test all skill logic

### Common Patterns

**Multi-Stage Analysis:**
```python
async def execute(self, args):
    # Stage 1: Initial analysis
    stage1 = await self.initial_analysis(args)

    # Stage 2: Deep analysis based on stage 1
    stage2 = await self.deep_analysis(stage1)

    # Stage 3: Generate report
    report = self.generate_report(stage1, stage2)

    return SkillResult.success_result(report)
```

**Conditional Execution:**
```python
async def execute(self, args):
    results = {}

    # Always run basic analysis
    results["basic"] = await self.basic_analysis(args)

    # Conditionally run advanced analysis
    if args.get("deep_mode"):
        results["advanced"] = await self.advanced_analysis(args)

    return SkillResult.success_result(results)
```

### Future Enhancements

- [ ] Skill marketplace for sharing skills
- [ ] Skill dependencies and version management
- [ ] Skill composition DSL
- [ ] Skill templates and scaffolding
- [ ] Skill performance profiling
- [ ] Skill result caching
- [ ] Skill parallelization
- [ ] Skill A/B testing framework

---

**Status:** Phase 4 (Implemented) ✅

**Next Steps:** Add more built-in skills, enhance loader

**Maintainer:** REVENG Development Team
