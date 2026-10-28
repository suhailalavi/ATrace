# AlaviTrace Architecture Specification (v1.0.0)

AlaviTrace is an authorized cybersecurity reconnaissance and security assessment framework designed to provide explainable, deterministic vulnerability identification, attack surface mapping, controlled validation, and AI-assisted contextualization.

---

## 1. Core Architectural Pipeline

AlaviTrace enforces strict separation of concerns across 8 sequential stages. Deterministic detection engines are the single source of truth; artificial intelligence is strictly restricted to contextualization and explanation.

```
+-------------------------------------------------------------------------------+
|                               1. DISCOVERY                                    |
|   - Target Validation (IPv4, Hostname, Domain)                                |
|   - Nmap Network Reconnaissance (SYN/Connect, Service Version -sV, Banner CPE) |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                         2. EVIDENCE COLLECTION                                |
|   - Passive HTTP/HTTPS Probing (Headers, Banners, Certs, TLS, Latency)        |
|   - Safe Disallowed Path Probing (robots.txt, security.txt, OPTIONS methods)   |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                              3. DETECTION                                     |
|   - Attack Surface Mapping (Endpoints, Methods, Parameters, Technologies)      |
|   - Deterministic Security Misconfiguration (Missing Headers, Debug Panels)   |
|   - OWASP Detection Engine (A01, A02, A03, A05, A06, A07, A10 Heuristics)     |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                            4. INTELLIGENCE                                    |
|   - NVD CVE Intelligence Correlation (CPE-based, Product/Version Matching)    |
|   - CVSS Metric Extraction and Confidence Scoring                             |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                              5. VALIDATION                                    |
|   - Controlled Finding Validation Framework (Bounded, Safe, Non-Destructive)   |
|   - Reflected Parameter, SQL Error Signature, Path Traversal, CSRF Checks     |
|   - Empirical Evidence Recording (VALIDATED, NOT_VALIDATED, INCONCLUSIVE)     |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                            6. PRIORITIZATION                                  |
|   - Deterministic Scoring (Severity + CVSS + Confidence + Exposure + ValBonus)|
|   - Candidate Ranking and Top-N Selection                                     |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                            7. AI ANALYSIS                                     |
|   - Sensitive Data Sanitization (Redaction of Passwords, Tokens, API Keys)    |
|   - Untrusted Data Isolation (Anti-Prompt Injection Guardrails)               |
|   - Gemini Explanatory Synthesis (Executive, Technical, Remediation)          |
+---------------------------------------+---------------------------------------+
                                        |
+---------------------------------------v---------------------------------------+
|                              8. REPORTING                                     |
|   - Top-Level Assessment & AssessmentSummary Aggregation                      |
|   - Deterministic OWASP Top 10 (2021) Coverage Accounting                     |
|   - Canonical Multi-Format Generation (JSON, Markdown, HTML)                  |
+-------------------------------------------------------------------------------+
```

---

## 2. Top-Level Data Models

The core data structures reside in [`alavitrace.core.models`](file:///d:/AlaviTrace/alavitrace/core/models.py):

- **`Assessment`**: The canonical container aggregating `Target`, `scan_metadata`, `hosts`, `services`, `http_results`, `attack_surface`, `findings`, `prioritized_findings`, `validation_results`, `owasp_coverage`, `ai_analysis`, and `summary`.
- **`AssessmentSummary`**: Concise quantitative metrics including total findings, severity distribution (Critical, High, Medium, Low, Info), validation outcomes (Validated, Not Validated, Inconclusive), service counts, endpoint inventory, attack surface score, and overall risk rating.
- **`Finding`**: Core entity representing an identified vulnerability or security observation, tracking `lifecycle_stage`, `technical_category`, `severity`, `confidence`, `priority_score`, `cvss`, `cve_ids`, `endpoint`, `parameter`, and `validation_result`.
- **`FindingLifecycle`**: Enum tracking the state machine progression:
  1. `DISCOVERED`
  2. `ANALYZED`
  3. `CORRELATED`
  4. `PRIORITIZED`
  5. `VALIDATION_ATTEMPTED`
  6. `VALIDATED` / `NOT_VALIDATED` / `INCONCLUSIVE`
  7. `REPORTED`

---

## 3. Strict Architectural Isolation & Guardrails

1. **Deterministic Single Source of Truth**: Vulnerabilities are discovered, correlated, and validated exclusively by deterministic Python engines. Gemini cannot create, validate, elevate, or suppress security findings.
2. **Untrusted Data Isolation**: All raw network inputs (banners, server headers, parameters, HTML snippets) are treated as untrusted strings. The AI system prompt strictly forbids executing commands embedded inside input text.
3. **Sensitive Data Sanitization**: Prior to dispatching structured evidence to external AI APIs, sensitive parameters (`password=...`, `token=...`, `secret=...`), Bearer tokens, Basic authorization headers, and AWS keys are automatically sanitized using regex masking (`[REDACTED]`).
4. **Offline Resilience**: The pipeline gracefully operates in fully air-gapped environments without external network egress using `--no-vuln-check` and `--no-ai`.
