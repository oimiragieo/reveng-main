# Reports Directory

## Overview

The `reports/` directory stores generated analysis reports, security audit results, and output from REVENG analysis runs. This directory is used for storing analysis artifacts and results.

**Purpose**: Store analysis reports, security audits, and REVENG output.

**Location**: `/home/user/reveng-main/reports/`

## Directory Contents

```
reports/
├── claude.md                  # This file
└── security/                  # Security-specific reports
    └── [security audit reports]
```

**Note**: Most report files are generated at runtime and excluded from git via `.gitignore`.

## Usage

### Generated Reports

REVENG generates various types of reports:

**Analysis Reports:**
- Binary analysis results
- Decompilation output
- Vulnerability findings
- Exploit generation results

**Security Reports:**
- Vulnerability assessments
- Security audit results
- Compliance reports
- Threat intelligence

**Format Options:**
- JSON - Machine-readable format
- HTML - Human-readable reports
- PDF - Publication-ready reports
- Markdown - Documentation format

### Generating Reports

```bash
# Generate analysis report
reveng analyze binary.exe --report reports/analysis_report.json

# Generate HTML report
reveng analyze binary.exe --report reports/report.html --format html

# Generate comprehensive report
reveng analyze binary.exe --report reports/full_report.pdf --format pdf
```

### Reading Reports

```python
# Read JSON report
import json

with open('reports/analysis_report.json') as f:
    report = json.load(f)

print(f"Functions analyzed: {len(report['functions'])}")
print(f"Vulnerabilities found: {len(report['vulnerabilities'])}")
```

## Related Directories

- **docs/reports/** - Report documentation and templates
- **examples/** - Example report generation scripts

## Notes

### Report Structure

**Typical JSON Report:**
```json
{
  "metadata": {
    "binary": "binary.exe",
    "analysis_date": "2025-01-15",
    "reveng_version": "3.0.0"
  },
  "analysis": {
    "functions": [...],
    "vulnerabilities": [...],
    "exploits": [...]
  }
}
```

### Storage

- Reports are gitignored by default
- Large reports stored locally only
- Consider external storage for production
- Implement retention policy for old reports

---

**Purpose**: Analysis output storage
**Default Format**: JSON
**Retention**: Configure as needed
