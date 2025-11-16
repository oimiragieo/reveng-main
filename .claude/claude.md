# .claude Directory

## Overview

The `.claude/` directory contains configuration files for Claude Code (Anthropic's AI assistant integration). This directory stores settings, preferences, and local configurations for AI-assisted development.

**Purpose**: Store Claude Code configuration and local settings.

**Location**: `/home/user/reveng-main/.claude/`

## Directory Contents

```
.claude/
├── claude.md                  # This file
└── settings.local.json        # Local Claude settings (229 bytes)
```

## Configuration

### Local Settings

**settings.local.json** (229 bytes)
- Claude Code preferences
- Local development settings
- AI assistant configuration
- Project-specific options

**Note**: This file is typically gitignored to keep personal preferences local.

## Usage

### Claude Code Integration

Claude Code uses this directory for:
- Storing conversation context
- Caching AI responses
- Project-specific configurations
- User preferences

### Configuration Options

Typical settings might include:
```json
{
  "model": "claude-sonnet-4-5",
  "maxTokens": 4096,
  "temperature": 0.7,
  "codeStyle": "pythonic",
  "autoFormat": true,
  "contextWindowSize": "large"
}
```

## Related Documentation

- **Claude Code Docs**: https://claude.ai/docs
- **AI Integration Guide**: `docs/guides/CLAUDE_INTEGRATION.md`
- **AI Assistant Guide**: `docs/guides/AI_ASSISTANT_GUIDE.md`

## Notes

### Privacy

- `.claude/` directory is gitignored
- Contains local settings only
- No sensitive data should be stored
- API keys use environment variables

### Best Practices

- Don't commit `.claude/` to git
- Use environment variables for secrets
- Keep configuration minimal
- Document custom settings

---

**Purpose**: Claude Code configuration
**Privacy**: Local only (gitignored)
**Usage**: AI-assisted development
