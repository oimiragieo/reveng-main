# Agent SDK - Built-in Skills

## Overview

This directory contains built-in skills that provide out-of-the-box capabilities for common reverse engineering tasks including code analysis, security audits, and vulnerability discovery.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/skills/builtin/`

## Files in This Directory

### `__init__.py` (355 lines)
Exports all built-in skills for easy access.

**Exports:**
- `CodeAnalysisSkill` - Automated code analysis
- `SecurityAuditSkill` - Comprehensive security auditing
- `VulnerabilityDiscoverySkill` - Automated vulnerability discovery

### `code_analysis.py` (2022 lines)
Automated code analysis skill.

**CodeAnalysisSkill:**
- **Purpose:** Analyze code structure, complexity, and quality
- **Input:** `code` (string or file path), `language` (optional), `depth` (quick/normal/deep)
- **Output:** Code metrics, complexity analysis, quality score

**Features:**
- Multi-language support
- Cyclomatic complexity calculation
- Code smell detection
- Quality scoring
- Refactoring suggestions

### `security_audit.py` (2988 lines)
Comprehensive security audit skill.

**SecurityAuditSkill:**
- **Purpose:** Complete security audit combining multiple analysis techniques
- **Input:** `binary_path` (string), `audit_type` (quick/standard/comprehensive)
- **Output:** Security report with vulnerabilities, malware indicators, exploit possibilities

**Audit Stages:**
1. Binary analysis and metadata extraction
2. Malware detection
3. Vulnerability scanning
4. Exploit possibility assessment
5. Security recommendations

**Features:**
- Multi-stage analysis pipeline
- Risk scoring
- Compliance checking
- Detailed reporting

### `vulnerability_discovery.py` (128 lines)
Automated vulnerability discovery skill.

**VulnerabilityDiscoverySkill:**
- **Purpose:** Discover vulnerabilities using pattern matching and heuristics
- **Input:** `target` (path), `type` (binary/code), `depth` (quick/normal/deep)
- **Output:** Vulnerability list with severity, CWE IDs, descriptions

**Detection Methods:**
- Pattern matching (eval, innerHTML, etc.)
- Static analysis
- Heuristic checks
- CWE mapping

**Vulnerability Types Detected:**
- Buffer overflow (CWE-120)
- Code injection (CWE-95)
- XSS (CWE-79)
- SQL injection (CWE-89)
- Path traversal (CWE-22)

## Architecture

### Skill Composition

```
SecurityAuditSkill (comprehensive)
  ├─> BinaryAnalysisTool
  ├─> VulnerabilityDiscoverySkill
  ├─> MalwareDetectionTool
  └─> ExploitAssessmentTool

VulnerabilityDiscoverySkill
  ├─> PatternMatcher
  ├─> StaticAnalyzer
  └─> HeuristicEngine

CodeAnalysisSkill
  ├─> ComplexityAnalyzer
  ├─> QualityChecker
  └─> RefactoringSuggester
```

## Usage Examples

### Example 1: Code Analysis

```python
from reveng.agent_sdk.skills.builtin import CodeAnalysisSkill

async def analyze_code():
    skill = CodeAnalysisSkill()

    result = await skill.execute({
        "code": "/path/to/source.py",
        "language": "python",
        "depth": "normal"
    })

    if result.success:
        metrics = result.output['metrics']
        print(f"Lines of code: {metrics['loc']}")
        print(f"Complexity: {metrics['complexity']}")
        print(f"Quality score: {metrics['quality_score']}/100")
```

### Example 2: Security Audit

```python
from reveng.agent_sdk.skills.builtin import SecurityAuditSkill

async def audit_binary():
    skill = SecurityAuditSkill()

    result = await skill.execute({
        "binary_path": "/path/to/app.exe",
        "audit_type": "comprehensive"
    })

    if result.success:
        report = result.output
        print(f"Risk Score: {report['risk_score']}/100")
        print(f"Vulnerabilities: {len(report['vulnerabilities'])}")
        print(f"Malware Indicators: {len(report['malware_indicators'])}")
```

### Example 3: Vulnerability Discovery

```python
from reveng.agent_sdk.skills.builtin import VulnerabilityDiscoverySkill

async def find_vulnerabilities():
    skill = VulnerabilityDiscoverySkill()

    result = await skill.execute({
        "target": "app.js",
        "type": "code",
        "depth": "deep"
    })

    if result.success:
        vulns = result.output['vulnerabilities']
        severity_summary = result.output['severity_summary']

        print(f"Critical: {severity_summary['critical']}")
        print(f"High: {severity_summary['high']}")
        print(f"Medium: {severity_summary['medium']}")

        for vuln in vulns:
            print(f"\n{vuln['type']} ({vuln['severity']})")
            print(f"  {vuln['description']}")
            print(f"  CWE: {vuln['cwe_id']}")
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/skills/` - Skills framework
- `/home/user/reveng-main/src/reveng/agent_sdk/tools/` - Tools used by skills

### External REVENG Integration
- `/home/user/reveng-main/src/reveng/analyzer/` - Binary analysis
- `/home/user/reveng-main/src/reveng/javascript/` - JS analysis
- `/home/user/reveng-main/src/reveng/security/` - Security features

## Notes

**Best Practices:**
1. Use appropriate depth level for analysis
2. Combine skills for comprehensive analysis
3. Review all vulnerability findings manually
4. Use skills as starting point, not final answer

**Future Enhancements:**
- [ ] ML-based vulnerability prediction
- [ ] Automated exploit generation
- [ ] Cross-reference with vulnerability databases
- [ ] Real-time analysis streaming

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
