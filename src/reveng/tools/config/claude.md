# Tools - Config

## Overview

Configuration management tools for REVENG, including loading, validation, and management of analysis configurations.

**Location:** `/home/user/reveng-main/src/reveng/tools/config/`

**File Count:** 6 Python files

## Key Capabilities

### Configuration Loading
- Load from YAML, JSON, TOML
- Environment variable substitution
- Default configuration management

### Configuration Validation
- Schema validation
- Type checking
- Required field validation

### Configuration Management
- Merge configurations
- Override settings
- Profile management

## Usage Examples

### Example 1: Load Configuration

```python
from reveng.tools.config import ConfigLoader

loader = ConfigLoader()
config = loader.load("reveng.yaml")

print(f"Analysis mode: {config['analysis']['mode']}")
print(f"Output dir: {config['output_dir']}")
```

### Example 2: Validate Configuration

```python
from reveng.tools.config import ConfigValidator

validator = ConfigValidator()
is_valid = validator.validate(config)

if not is_valid:
    print(f"Errors: {validator.errors}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/core/` - Core configuration
- `/home/user/reveng-main/src/reveng/utils/` - Utility functions

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
