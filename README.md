# AlaviTrace

**AI-Assisted Reconnaissance & Security Intelligence Framework**

AlaviTrace is an educational security intelligence orchestrator designed to automate repetitive early-stage reconnaissance and enumeration while keeping the human penetration tester in control of key security decisions.

---

## Current MVP Capabilities (v0.1 - Phase 5 Complete)

- **Target Input & Validation**: Strict validation and normalization of IPv4 addresses, domains, and hostnames.
- **Safe Nmap Orchestration**: Safe execution of Nmap service detection (`-sV`) using Python's `subprocess.run(shell=False)` with temporary XML file management.
- **Robust XML Parsing**: Parsing Nmap XML into structured Python models (`ScanResult`, `Host`, `Service`) using standard library `xml.etree.ElementTree`.
- **Passive HTTP/HTTPS Enumeration**: Non-intrusive HTTP metadata extraction (`Server`, `X-Powered-By`, response latency, redirect tracking).
- **Security Header Analysis**: Evaluation of 6 key HTTP security headers (`HSTS`, `CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`).
- **Deterministic Recommendations**: Rule-based security hardening recommendations based on observed header configurations.
- **Vulnerability Intelligence & CVE Correlation**: NVD API v2 integration with CPE 2.2 to 2.3 conversion, local disk caching, rate-limit resilience, and confidence tagging (`PROBABLE`/`POTENTIAL`).
- **Vulnerability Prioritization & Finding Deduplication (Phase 4.1)**: Deterministic scoring formula (Severity + CVSS + Confidence + Open Port exposure), primary CVE deduplication, multi-port evidence merging, configurable `--max-findings` Top-N candidate selection (default: 5), and 100% raw data retention in JSON output.
- **AI-Assisted Security Analysis**: Google Gemini API integration (`google-genai` SDK) providing executive summaries, attack surface analysis, and manual investigation guidance over prioritized evidence JSON with strict candidate wording guardrails.
- **Multi-Format Reporting Engine**: Automated generation of machine-readable JSON (with full retained dataset), developer-friendly Markdown, and styled standalone HTML reports.
- **Offline Test Suite**: 54 automated unit tests covering validation, scanner error handling, XML parsing, HTTP response mocking, NVD API mocking, vulnerability prioritization & deduplication, AI provider fallback, and multi-format report generation.

> [!IMPORTANT]
> **Deterministic Evidence vs AI Explanation**: AlaviTrace uses established security tools and deterministic correlation for evidence collection. AI is introduced strictly as an explanatory layer over collected evidence—it does **not** perform autonomous exploitation or command execution.

---

## Documentation Index

- [Target Validation](docs/nmap.md)
- [Nmap Reconnaissance & Parsing](docs/nmap.md)
- [Passive HTTP Enumeration](docs/http-enumeration.md)
- [Vulnerability Intelligence](docs/vulnerability-intelligence.md)
- [Vulnerability Prioritization & Deduplication](docs/vulnerability-prioritization.md)
- [AI Analysis Layer](docs/ai-analysis.md)
- [Reporting Engine](docs/reporting.md)

---

## Long-Term Vision & Roadmap

- **v0.1 MVP**: Target Validation, Nmap Reconnaissance, XML Parsing, Passive HTTP Inspection, Deterministic Recommendations, Vulnerability Intelligence, AI-Assisted Analysis, Multi-format Reporting.
- **v0.2**: Additional service modules (SMB, FTP, DNS), passive TLS certificate analysis.
- **v0.3**: Advanced web application configuration auditing.
- **v0.4**: Guided vulnerability validation workflows.
- **v1.0**: Authorized lab-only controlled exploitation framework integration.

---

## Quickstart & Usage

### 1. Installation

```bash
git clone https://github.com/user/AlaviTrace.git
cd AlaviTrace
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. Running Complete Assessment Pipeline

```bash
# Set Gemini API key (Optional)
set GEMINI_API_KEY=your_gemini_api_key  # Windows
export GEMINI_API_KEY="your_gemini_api_key"  # Linux/macOS

# Run full assessment pipeline against lab target
python -m alavitrace.cli --target 192.168.56.106 --pn --format all
```

### 3. Running Unit Tests

```bash
python -m pytest tests/
```

---

## Authorized Use & Disclaimer

> [!CAUTION]
> **Authorization Requirement**: AlaviTrace is designed strictly for educational purposes, personal lab environments (e.g., Metasploitable, VulnHub Sunset), and authorized penetration testing engagements. Unauthorized scanning or testing of external targets is strictly illegal.
