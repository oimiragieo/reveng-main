# REVENG Core

## Overview

The core module provides fundamental infrastructure for the REVENG framework including configuration management, logging, error handling, and base abstractions used throughout the system.

**Location:** `/home/user/reveng-main/src/reveng/core/`

## Key Components

### Configuration Management
- System-wide configuration
- Plugin configuration
- User preferences
- Environment settings

### Logging
- Structured logging
- Log levels and formatting
- Log rotation
- Multiple output targets

### Error Handling
- Exception hierarchy
- Error reporting
- Stack traces
- Error recovery

### Base Classes
- Abstract base classes
- Common interfaces
- Mixins and utilities
- Design patterns

## Architecture

The core module serves as the foundation for all REVENG components:

```
Core Module
  ├─> Configuration System
  ├─> Logging System
  ├─> Error Handling
  ├─> Base Classes
  └─> Common Utilities
```

## Usage Examples

### Example 1: Configuration

```python
from reveng.core import config

# Load configuration
cfg = config.load_config()

# Access settings
output_dir = cfg.get("output_dir")
log_level = cfg.get("logging.level")
```

### Example 2: Logging

```python
from reveng.core.logger import get_logger

logger = get_logger()

logger.info("Starting analysis...")
logger.debug("Debug information")
logger.error("Error occurred", exc_info=True)
```

### Example 3: Error Handling

```python
from reveng.core.errors import REVENGError, AnalysisError

try:
    # Perform analysis
    result = analyze_binary(path)
except AnalysisError as e:
    logger.error(f"Analysis failed: {e}")
except REVENGError as e:
    logger.error(f"REVENG error: {e}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/types/` - Type definitions
- `/home/user/reveng-main/src/reveng/utils/` - Utility functions
- `/home/user/reveng-main/src/reveng/validation/` - Validation utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
