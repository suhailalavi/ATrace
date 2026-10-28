# Advanced Web Vulnerability Validation (Phase 11)

## 1. Overview & Objective

**Phase 11** advances AlaviTrace's controlled validation framework by integrating structured **attack-surface mapping** (introduced in Phase 10) with **conservative, empirical, non-destructive web validation modules**.

Rather than relying on static banner guessing or speculative CVE associations, Phase 11 probes discovered application endpoints, parameters, and form handlers with benign syntax probes to verify whether vulnerability indicators are observable in real time.

```
+-------------------------------------------------------------------------------+
|                       ALAVITRACE PIPELINE ARCHITECTURE                        |
+-------------------------------------------------------------------------------+
|  Phase 1: Target Validation                                                   |
|  Phase 2: Nmap Service & CPE Discovery                                        |
|  Phase 3: Passive HTTP Enumeration & Security Headers                         |
|  Phase 10: Attack Surface Mapping & Web Endpoint Discovery                   |
|  Phase 4: Vulnerability Intelligence (NVD CVE Correlation)                   |
|  Phase 6-8: OWASP Security Assessment (A01, A03, A05, A06, A07)               |
|  Phase 4.1: Vulnerability Prioritization & Deduplication                      |
|                                                                               |
|  Phase 11: ADVANCED WEB VULNERABILITY VALIDATION                              |
|    - Attack-Surface-Guided Endpoint & Parameter Targeting                     |
|    - Conservative Error Signature & Canary Reflection Checks                  |
|    - Strict Non-Destructive Safety Boundary (Zero Exploitation)               |
|    - Prioritization Re-Scoring (+30 VALIDATED, -15 NOT_VALIDATED)             |
|                                                                               |
|  Phase 5: AI-Assisted Security Analysis (Gemini Explanation with Rule 8)      |
|  Reporting: JSON, Markdown, HTML Multi-Format Reports                         |
+-------------------------------------------------------------------------------+
```

---

## 2. Strict Safety Policy & Ethical Guardrails

Phase 11 is **strictly non-destructive**. It is engineered for authorized security assessment and audit workflows:

| Restricted Action | Policy & Enforcement |
| :--- | :--- |
| **Reverse Shells / RCE** | **Prohibited.** Command injection candidates are permanently marked `NOT_APPLICABLE` without executing OS commands. |
| **Destructive SQL** | **Prohibited.** No `DROP`, `DELETE`, `UPDATE`, `INSERT`, `--`, or stacked queries. Only benign single-quote syntax checks (`'`) are permitted. |
| **Data Extraction** | **Prohibited.** Zero `UNION SELECT`, zero database table enumeration, zero sensitive data dumping. |
| **Brute Force / Credential Stuffing** | **Prohibited.** Zero automated authentication attempts, zero dictionary spraying. |
| **State-Changing Form Submissions** | **Prohibited.** CSRF evaluation inspects forms and session cookies passively; forms are never submitted. |
| **Internal SSRF Probing** | **Prohibited.** The validation engine explicitly blocks requests to `127.0.0.1`, `localhost`, `169.254.169.254`, and cloud metadata endpoints. |
| **Off-Scope Network Calls** | **Prohibited.** Outbound requests to third-party or off-scope hosts (even via redirects) are rejected. |
| **Unbounded Requests** | **Enforced.** Bounded by `--max-validation-requests` (default: 20). Requests halt gracefully if the budget is reached. |

---

## 3. Specialized Validator Suite & Precedence

Validation candidates are evaluated by dedicated validators managed by `ValidatorRegistry`. Validators are evaluated in deterministic priority order:

| Precedence | Validator | Scope & Method | Outcome Semantics |
| :---: | :--- | :--- | :--- |
| **1** | `SQLInjectionValidator` | Delimiter probe (`'`) against discovered parameters; checks for 5 database error signatures (MySQL, PostgreSQL, SQLite, MSSQL, Oracle). | `VALIDATED` if error signature detected; `NOT_VALIDATED` if handled normally; zero data dumping. |
| **2** | `ReflectedXSSValidator` | Probes parameters with benign canary marker (`atracecanary987`); differentiates plain-text, HTML body, and dangerous script contexts. | `VALIDATED` if canary reflected in body; `NOT_VALIDATED` if not reflected. |
| **3** | `PathTraversalValidator` | Supplies harmless relative probe (`....//atrace_traversal_canary_test`); inspects for path error disclosures (`open_basedir`, `failed to open stream`). | `VALIDATED` if path error disclosed; `NOT_VALIDATED` if normal response; zero private files accessed. |
| **4** | `CommandInjectionValidator` | Matches OS command injection candidates; enforces safety policy. | Always returns `NOT_APPLICABLE`. |
| **5** | `CSRFValidator` | Evaluates POST form fields for anti-CSRF tokens and checks session cookies for `SameSite` flags without submitting forms. | `VALIDATED` if unprotected state-changing POST form detected; `NOT_VALIDATED` if protected. |
| **6** | `SSRFCandidateValidator` | Identifies SSRF parameters (`url`, `redirect`, `webhook`) without outbound callback queries. | Returns `NOT_VALIDATED` with candidate notes; zero internal or external probes. |
| **7** | `IDORCandidateValidator` | Identifies direct object references (`/user/123`, `id=123`) in paths and parameters without account substitution. | Returns `NOT_VALIDATED` with test candidate notes; zero account manipulation. |
| **8** | `AuthenticationSecurityValidator` | Analyzes transport security (HTTP vs HTTPS) and session cookie flags (`HttpOnly`, `Secure`, `SameSite`). | `VALIDATED` if missing recommended security attributes or cleartext login. |
| **9** | `HeaderValidator` | Verifies presence or absence of recommended HTTP security headers (`HSTS`, `CSP`, `X-Frame-Options`, etc.). | `VALIDATED` if missing header confirmed absent; `NOT_VALIDATED` if present. |
| **10** | `MisconfigurationValidator` | Verifies directory listings (`Index of /`), exposed banners, and HTTP `TRACE` method support. | `VALIDATED` if misconfiguration confirmed; `NOT_VALIDATED` otherwise. |
| **11** | `ResponseBehaviorValidator` | Verifies status codes and error page behavior divergence. | `VALIDATED` / `NOT_VALIDATED` based on status code matching. |
| **12** | `ServicePresenceValidator` | Performs non-destructive TCP socket connect (`connect_ex`) to verify port reachability for CVE findings. | `VALIDATED` if TCP port open; `NOT_VALIDATED` if port closed. |
| **13** | `FallbackValidator` | Catches unsupported or untestable finding categories. | Returns `NOT_APPLICABLE`. |

---

## 4. Prioritization Integration & Re-Ranking

Empirical validation directly influences the AlaviTrace prioritization score:

$$\text{Final Score} = \text{Base Score} + \text{Validation Adjustment}$$

- **`VALIDATED`**: **+30 points** — Empirical technical evidence confirms the condition is active, elevating it to high-priority remediation.
- **`NOT_VALIDATED`**: **-15 points** — Testing was performed but the vulnerability indicator was absent or mitigated.
- **`INCONCLUSIVE` / `NOT_APPLICABLE`**: **0 points** — Insufficient evidence or policy restriction; maintains base score.

Following validation, findings are re-sorted dynamically so verified findings bubble to the top of all summaries and reports.

---

## 5. CLI Usage & Flags

Enable validation using the `--validate` flag:

```bash
# Basic scan with validation enabled
python -m alavitrace -t 192.168.56.101 --validate

# Scan with attack surface discovery and custom validation limits
python -m alavitrace -t 192.168.56.101 --attack-surface --validate --max-validation-requests 30 --validation-timeout 5

# Full audit pipeline generating all report formats
python -m alavitrace -t 192.168.56.101 --attack-surface --owasp --injection --validate --format all
```

### Validation CLI Arguments

| Argument | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `--validate` | Flag | `False` | Enables the controlled finding validation framework. |
| `--validation-timeout` | Integer | `5` | Per-request timeout in seconds for validation probes. |
| `--max-validation-requests` | Integer | `10` | Maximum total HTTP requests permitted across all validation checks. |

---

## 6. AI & Reporting Integration

1. **AI System Prompt Guardrails (Rule 8):**
   The Gemini reasoning layer is bound by explicit system rules:
   > *"When explaining web validation evidence (such as reflected parameter probes, SQL error indicators, path traversal markers, CSRF forms, or candidate parameters), clearly explain what was observed and what limitations apply. Do NOT claim remote code execution, database compromise, or administrative bypass occurred. Strictly respect validator limitation notes and empirical boundaries."*

2. **JSON Reports (`reports/*.json`):**
   Includes `validation_summary` block with request counts, candidate totals, status counts, and per-finding `validation` objects containing `structured_evidence` and `limitations`.

3. **Markdown Reports (`reports/*.md`):**
   Includes a dedicated `Controlled Finding Validation Summary` table detailing validation method, empirical evidence, and limitation notes.

4. **HTML Reports (`reports/*.html`):**
   Renders validation badges (`badge-VALIDATED`, `badge-NOT_VALIDATED`, `badge-INCONCLUSIVE`, `badge-NOT_APPLICABLE`, `badge-ERROR`) and displays detailed methodology limitations.
