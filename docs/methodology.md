# AlaviTrace Assessment Methodology (v1.0.0)

AlaviTrace follows an evidence-based, deterministic assessment methodology designed to provide security teams with actionable intelligence while preventing target destabilization.

---

## 1. Reconnaissance & Discovery

- **Target Scope Validation**: All user inputs are parsed into IPv4, Hostname, or Domain targets. Loopback (`127.0.0.1`), private RFC 1918 subnets, and public routable targets must be explicitly authorized.
- **Service & Banner Detection**: Nmap is orchestrated in non-destructive `-sV` mode to detect open TCP ports, banners, and CPE strings.
- **Passive HTTP Inspection**: Discovered HTTP/HTTPS services are queried with benign `GET` and `HEAD` probes to record headers, TLS certificate metadata, and redirect chains.

---

## 2. Attack Surface Mapping

- **Bounded Web Crawling**: Bounded recursive crawling maps local application routes up to configurable limits (default: depth 2, max 20 requests).
- **Surface Extraction**: Extracts endpoints, observed query parameters, HTML form elements (`action`, `method`, `input`), and technology signatures.

---

## 3. Vulnerability Intelligence & Correlation

- **CPE-to-CVE Correlation**: Services with extracted CPEs are matched against the National Vulnerability Database (NVD) API v2.
- **Confidence Classification**: Matches are categorized as `CONFIRMED`, `PROBABLE`, or `POTENTIAL` based on version precision and vendor matching.

---

## 4. Deterministic Prioritization Scoring Formula

Prioritization uses an explainable formula combining base severity, CVSS scores, confidence weights, exposure factors, and empirical validation bonuses:

$$\text{Priority Score} = \text{Severity Weight} + \text{Confidence Weight} + \text{CVSS Weight} + \text{Exposure Bonus} + \text{Validation Bonus}$$

### Factor Weights:
- **Severity**: Critical (100), High (75), Medium (50), Low (25), Informational (5)
- **Confidence**: Probable (50), Confirmed (50), Observed (45), Potential (25), Informational (10)
- **CVSS Score**: $\text{int}(\text{CVSS} \times 10)$ (up to 100 points)
- **Exposure**: +20 points if an exposed port or HTTP endpoint is verified
- **Validation**:
  - `VALIDATED`: **+30 points**
  - `NOT_VALIDATED`: **-15 points**
  - `INCONCLUSIVE` / `NOT_APPLICABLE`: **0 points**

---

## 5. Controlled Finding Validation

Validation modules collect non-destructive empirical evidence:
- **Reflected Parameter Validator**: Sends benign, inert alphanumeric canary strings (e.g., `atrace_xss_<token>`) to test whether user input reflects into HTML contexts without encoding.
- **SQL Error Signature Validator**: Probes parameters with benign punctuation markers and inspects responses for specific database error patterns (MariaDB, PostgreSQL, SQLite, MSSQL, Oracle).
- **Path Traversal Validator**: Tests for benign system root file exposure using bounded directory traversal strings.
- **CSRF Validator**: Analyzes HTML forms to identify missing anti-forgery tokens on state-changing `POST` actions.

---

## 6. AI Explanation & Reporting

- **Explanation Role**: Gemini contextualizes verified findings into executive summaries, key observations, and actionable remediation steps.
- **Multi-Format Reports**: JSON for automation and SIEM ingest; Markdown for GitHub/GitLab PRs; standalone interactive HTML dashboards for executive review.
