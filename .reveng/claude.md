# .reveng Directory

## Overview

The `.reveng/` directory contains REVENG-specific configuration files, validation policies, and project settings. This directory stores configuration for REVENG's security policies, validation rules, and operational parameters.

**Purpose**: REVENG configuration, security policies, and validation rules.

**Location**: `/home/user/reveng-main/.reveng/`

## Directory Contents

```
.reveng/
├── claude.md                      # This file
├── config.yaml                    # REVENG configuration (1,348 bytes)
├── validation.yaml.example        # Validation config example (3,141 bytes)
└── validation_policy.json         # Validation policies (1,836 bytes)
```

## Key Files

### Configuration

**config.yaml** (1,348 bytes)
- REVENG operational configuration
- Default settings
- Feature toggles
- Performance parameters

**Example structure:**
```yaml
reveng:
  version: "3.0.0"

  analysis:
    timeout: 300
    max_functions: 10000
    parallel_jobs: 4

  ai:
    enabled: true
    provider: "gemini"
    max_tokens: 4096

  security:
    enable_sandbox: true
    max_file_size: 104857600  # 100MB
    allowed_extensions: [".exe", ".dll", ".so"]
```

### Validation

**validation.yaml.example** (3,141 bytes)
- Example validation configuration
- Input validation rules
- Security policies
- File type restrictions

**validation_policy.json** (1,836 bytes)
- Validation policy definitions
- Security constraints
- Compliance rules
- Access controls

**Example structure:**
```json
{
  "policies": {
    "file_validation": {
      "max_size": 104857600,
      "allowed_types": ["PE", "ELF", "Mach-O"],
      "require_signature": false
    },
    "security": {
      "sandbox_required": true,
      "network_isolation": true,
      "timeout_seconds": 300
    }
  }
}
```

## Usage

### Loading Configuration

```python
# Load REVENG configuration
from reveng.core.config import load_config

config = load_config('.reveng/config.yaml')

# Access configuration
timeout = config.analysis.timeout
ai_enabled = config.ai.enabled
```

### Validation Policies

```python
# Load validation policies
from reveng.core.validation import ValidationPolicy

policy = ValidationPolicy.load('.reveng/validation_policy.json')

# Validate file
if not policy.validate_file(binary_path):
    raise ValidationError("File failed validation")
```

### Custom Configuration

```bash
# Copy example validation config
cp .reveng/validation.yaml.example .reveng/validation.yaml

# Edit configuration
vim .reveng/config.yaml

# REVENG will use custom configuration
```

## Configuration Options

### Analysis Settings

- **timeout**: Maximum analysis time (seconds)
- **max_functions**: Max functions to analyze
- **parallel_jobs**: Parallel analysis jobs
- **cache_results**: Enable result caching
- **verbose**: Enable verbose logging

### AI Settings

- **enabled**: Enable/disable AI features
- **provider**: AI provider (gemini, claude, gpt4)
- **api_key_env**: Environment variable for API key
- **max_tokens**: Maximum tokens per request
- **temperature**: AI temperature (0.0-1.0)

### Security Settings

- **enable_sandbox**: Isolate analysis
- **max_file_size**: Maximum binary size
- **allowed_extensions**: Permitted file types
- **network_isolation**: Block network access
- **require_signature**: Require code signing

## Related Documentation

- **Configuration Guide**: `docs/user-guide/USER_GUIDE.md`
- **Security Policy**: `/home/user/reveng-main/SECURITY.md`
- **Developer Guide**: `docs/developer-guide/DEVELOPER_GUIDE.md`

## Notes

### Configuration Hierarchy

REVENG loads configuration from (in order):
1. Default built-in configuration
2. `.reveng/config.yaml` (project-level)
3. `~/.reveng/config.yaml` (user-level)
4. Environment variables
5. Command-line arguments

Later sources override earlier ones.

### Environment Variables

Configuration can use environment variables:
```yaml
ai:
  api_key: ${GEMINI_API_KEY}

database:
  connection_string: ${DATABASE_URL}
```

### Security

**Important:**
- Never commit API keys to config
- Use environment variables for secrets
- Review validation policies regularly
- Keep configuration files secure

### Validation Policies

**Purpose:**
- Enforce security constraints
- Validate input files
- Prevent malicious inputs
- Ensure compliance

**Best Practices:**
- Start with strict policies
- Relax only when necessary
- Log all validation failures
- Review policies regularly

### Customization

Users can customize:
- Analysis parameters
- AI provider and settings
- Security policies
- Validation rules
- Output formats
- Logging levels

---

**Purpose**: REVENG configuration and policies
**Format**: YAML and JSON
**Scope**: Project-wide settings
**Security**: Review policies regularly
