# AlaviTrace End-to-End Assessment Guide (v1.0.0)

This guide documents the usage, CLI flags, execution flows, and report outputs for AlaviTrace v1.0.0.

---

## 1. Quick Start

### Basic Assessment (All Features Enabled)
```bash
python -m alavitrace.cli 192.168.56.106 --owasp --validate --attack-surface
```

### Full Multi-Format Report Generation
```bash
python -m alavitrace.cli example.com --owasp --validate --attack-surface --format all --output-dir ./reports
```

### Air-Gapped / Offline Assessment
```bash
python -m alavitrace.cli 127.0.0.1 --no-vuln-check --no-ai --format markdown
```

---

## 2. CLI Options Reference

| Option | Description | Default |
| :--- | :--- | :--- |
| `target` | Target IPv4 address, hostname, or domain | *Required* |
| `--verbose`, `-v` | Enable verbose diagnostic logging | `False` |
| `-Pn` | Skip Nmap ping/host discovery | `False` |
| `--keep-xml` | Retain temporary Nmap XML output file | `False` |
| `--no-vuln-check` | Skip external NVD CVE intelligence queries | `False` |
| `--vuln-provider` | Vulnerability intelligence provider | `nvd` |
| `--max-findings` | Maximum prioritized candidates to highlight | `5` |
| `--no-ai` | Disable Gemini AI contextual analysis | `False` |
| `--owasp` | Enable OWASP Web Security Assessment Engine | `False` |
| `--injection` | Enable controlled web injection probes | `False` |
| `--max-injection-requests` | Max requests per parameter for injection checks | `10` |
| `--misconfig` | Enable security misconfiguration auditing | `True` |
| `--validate` | Enable Controlled Finding Validation Framework | `False` |
| `--validation-timeout` | Timeout in seconds per validation request | `5.0` |
| `--max-validation-requests` | Max requests per finding during validation | `10` |
| `--attack-surface` | Enable web attack-surface mapping & endpoint discovery | `False` |
| `--max-depth` | Maximum crawling recursion depth | `2` |
| `--max-requests` | Maximum HTTP requests during surface mapping | `20` |
| `--output-dir`, `-o` | Output directory for assessment reports | `reports` |
| `--format`, `-f` | Report formats: `json`, `markdown`, `html`, or `all` | `all` |

---

## 3. Interpreting Assessment Reports

Every assessment generates canonical reports inside the output directory:

### JSON Report (`alavitrace_<timestamp>.json`)
Machine-readable report suitable for SIEM, CI/CD, or automated compliance ingestion. Contains:
- `summary`: High-level metrics, overall risk rating, attack surface score.
- `owasp_coverage`: Deterministic coverage statistics across all 10 OWASP categories.
- `findings`: Prioritized findings with `lifecycle_stage`, `technical_category`, `cvss`, `priority_score`, and `validation`.
- `all_findings`: The full unfiltered corpus of correlated findings.
- `attack_surface`: Full inventory of discovered routes, methods, forms, and technologies.
- `ai_analysis`: Structured AI analysis (executive summary, priorities, remediation).

### Markdown Report (`alavitrace_<timestamp>.md`)
Human-readable report formatted in GitHub Flavored Markdown:
- Executive Risk Rating Banner (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
- Executive Assessment Metrics Table
- OWASP Top 10 (2021) Coverage Matrix
- Discovered Services & Network Reconnaissance
- Attack Surface Inventory
- Prioritized Findings & Validation Evidence
- Remediation Guidance

### HTML Report (`alavitrace_<timestamp>.html`)
Standalone, responsive HTML dashboard with color-coded severity badges, OWASP coverage table, and interactive finding views.
