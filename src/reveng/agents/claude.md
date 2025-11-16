# Directory: src/reveng/agents

## Overview
This directory contains agent-based components for automated reverse engineering. It includes AI-enhanced analyzers and automated analysis agents that can perform complex multi-step analysis tasks.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization
- **Dependencies**: None
- **Used By**: Various REVENG components

## Architecture

```
┌─────────────────────────────────────┐
│   Agent Layer                       │
├─────────────────────────────────────┤
│ • Automated analysis agents         │
│ • AI-enhanced analyzers             │
│ • Multi-step orchestration          │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │  ai/           │
       │  Submodule     │
       └────────────────┘
```

## Key Concepts

### Agent-Based Analysis
Agents automate complex reverse engineering workflows by:
- Breaking down complex tasks into steps
- Making intelligent decisions based on intermediate results
- Adapting analysis strategy based on findings
- Coordinating multiple tools and techniques

## Related Modules

### Subdirectories
- `src/reveng/agents/ai/`: AI-enhanced analysis agents (see separate claude.md)

### Used By
- `src/reveng/analyzer.py`: Uses agents for enhanced analysis
- `src/reveng/ai/`: AI components coordinate with agents

## Notes

### Design Philosophy
The agents module follows an autonomous agent pattern where agents can:
1. Receive high-level goals
2. Plan analysis strategies
3. Execute multi-step workflows
4. Adapt based on results
5. Report findings

### Future Enhancements
- Multi-agent coordination
- Learning from previous analyses
- Distributed agent execution
- Agent marketplace/plugins
