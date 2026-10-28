# AlaviTrace (v1.0.0)

**AI-Assisted Reconnaissance & Security Intelligence Framework**

AlaviTrace is an authorized cybersecurity reconnaissance and vulnerability assessment framework. It provides deterministic vulnerability identification, web attack-surface mapping, controlled validation, and AI-assisted contextualization while keeping human security professionals in command.

---

## Key Capabilities (v1.0.0 Release)

- **Target Input & Scope Validation**: Strict validation and normalization of IPv4 addresses, hostnames, and domain names.
- **Safe Network Reconnaissance**: Orchestration of Nmap service detection (`-sV`) with structured XML parsing (`ScanResult`, `Host`, `Service`).
- **Passive HTTP/HTTPS Enumeration**: Non-intrusive metadata extraction (status codes, headers, TLS certificates, cookies, forms, disallowed paths).
- **Security Misconfiguration & Header Auditing**: Comprehensive rule-based evaluation of HTTP defensive headers, default pages, and legacy protocols.
- **Attack Surface Mapping & Endpoint Discovery**: Bounded recursive crawling mapping URLs, forms, parameters, HTTP methods, and technology stacks.
- **Vulnerability Intelligence & CVE Correlation**: NVD API v2 integration with CPE 2.2/2.3 conversion, local caching, rate-limit resilience, and CVSS extraction.
- **Controlled Finding Validation Framework**: Safe, non-destructive validation modules verifying reflected parameters, SQL error signatures, path traversal indicators, and CSRF token absence.
- **Deterministic Prioritization Engine**: Explainable scoring formula combining Severity, CVSS score, Confidence, Service Exposure, and Empirical Validation bonuses.
- **Deterministic OWASP Top 10 (2021) Coverage Engine**: Honest accounting of 7 supported categories and 3 architectural review boundaries.
- **AI-Assisted Security Analysis**: Google Gemini API integration with prompt injection defenses and automated sensitive data sanitization (passwords, tokens, keys).
- **Multi-Format Reporting Engine**: Generates canonical machine-readable JSON, developer-ready Markdown, and standalone interactive HTML dashboards.
- **100% Offline Test Suite**: **234 automated unit tests** passing in ~2.0 seconds with zero-socket offline regression validation.

---

## Core Architecture Pipeline

```
[Target Validation] -> [Nmap Discovery] -> [HTTP Enumeration] -> [Attack Surface Mapping]
                                                                        |
                                                                        v
[Reporting Engine]  <- [Gemini AI Analysis] <- [Prioritization] <- [Controlled Validation]
 (JSON / MD / HTML)     (Sanitized Evidence)   (Scoring Formula)    (Non-Destructive Proof)
```

---

## Documentation Index

- [Architecture Specification (v1.0.0)](docs/architecture.md)
- [Assessment Methodology](docs/methodology.md)
- [Operational Security Boundaries](docs/security-boundaries.md)
- [OWASP Top 10 (2021) Coverage Guide](docs/owasp-coverage.md)
- [End-to-End Assessment Guide](docs/final-assessment.md)
- [Attack Surface Mapping](docs/attack-surface.md)
- [Controlled Finding Validation](docs/validation.md)
- [Advanced Web Validation](docs/advanced-validation.md)
- [Vulnerability Intelligence](docs/vulnerability-intelligence.md)
- [AI Analysis Layer](docs/ai-analysis.md)
- [Reporting Engine](docs/reporting.md)

---

## Quickstart & Usage

### 1. Installation

```bash
git clone https://github.com/user/AlaviTrace.git
cd AlaviTrace
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### 2. Running an Assessment

```bash
# Set Gemini API key (Optional for AI analysis)
set GEMINI_API_KEY=your_gemini_api_key  # Windows
export GEMINI_API_KEY="your_gemini_api_key"  # Linux/macOS

# Standard assessment with OWASP, Attack Surface, and Validation enabled
python -m alavitrace.cli 192.168.56.106 --owasp --validate --attack-surface --format all

# Air-gapped / offline assessment
python -m alavitrace.cli 127.0.0.1 --no-vuln-check --no-ai --format markdown
```

### 3. Running Test Suite

```bash
pytest tests/
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
