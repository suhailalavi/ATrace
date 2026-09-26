# Multi-Format Reporting Engine

## Overview

In **AlaviTrace v0.1 (Phase 5)**, the multi-format reporting engine converts structured reconnaissance evidence, passive web findings, correlated vulnerability records, and AI-assisted analysis into standalone, professional reports in **JSON**, **Markdown**, and **HTML** formats.

---

## Supported Report Formats

### 1. JSON Report (`.json`)
- **Purpose**: Machine-readable export for SIEM integration, automated pipeline processing, or archival.
- **Structure**: Contains top-level `metadata`, `reconnaissance`, `http_enumeration`, `findings`, and `ai_analysis` nodes.

### 2. Markdown Report (`.md`)
- **Purpose**: Human-readable markdown document suitable for GitHub repositories, documentation sites, or developer handoffs.
- **Features**: Includes GitHub Flavored Markdown alerts (`> [!NOTE]`), tables for open services and findings, and detailed remediation sections.

### 3. Standalone HTML Report (`.html`)
- **Purpose**: Self-contained web report suitable for management review or client presentations.
- **Features**: Clean CSS layout, responsive tables, color-coded severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and clear executive summary cards. Requires no external CSS/JS dependencies.

---

## CLI Options & Usage

Generate reports automatically using the `--format` and `--output-dir` arguments:

```bash
# Generate all report formats (JSON, Markdown, HTML) in reports/
python -m alavitrace.cli --target 192.168.56.106 --pn --format all

# Generate only JSON report in a custom folder
python -m alavitrace.cli --target 192.168.56.106 --pn --format json --output-dir audit_reports/

# Skip AI analysis but generate full deterministic reports
python -m alavitrace.cli --target 192.168.56.106 --pn --no-ai
```

---

## Output Filename Convention

Report files are saved with timestamps to prevent accidental overwriting:

```text
reports/
├── alavitrace_20260926_204637.json
├── alavitrace_20260926_204637.md
└── alavitrace_20260926_204637.html
```
