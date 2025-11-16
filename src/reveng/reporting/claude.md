# REVENG Reporting

## Overview

Reporting module for generating comprehensive analysis reports in various formats including PDF, HTML, Markdown, and JSON.

**Location:** `/home/user/reveng-main/src/reveng/reporting/`

## Key Features

### Report Formats
- PDF reports
- HTML reports
- Markdown reports
- JSON export
- XML export

### Report Content
- Executive summary
- Technical details
- Visualizations
- Code snippets
- IOCs

### Customization
- Templates
- Branding
- Custom sections
- Styling

## Usage Examples

### Example 1: Generate PDF Report

```python
from reveng.reporting import ReportGenerator

generator = ReportGenerator()
report = generator.generate(
    analysis_results=results,
    format="pdf",
    output="/path/to/report.pdf"
)

print(f"Report generated: {report['path']}")
```

### Example 2: Custom Template

```python
from reveng.reporting import ReportGenerator

generator = ReportGenerator(template="/path/to/template.html")
report = generator.generate(
    analysis_results=results,
    format="html",
    custom_sections=["executive_summary", "iocs"]
)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/reporting/visualization/` - Report visualizations

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
