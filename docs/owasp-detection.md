# OWASP Web Vulnerability Detection Engine (Phase 7)

## 1. Overview & Objectives

**Phase 7** introduces the **OWASP Web Vulnerability Detection Engine** to **AlaviTrace**, providing deterministic, non-destructive, and evidence-grounded assessment checks across discovered web services.

The engine executes controlled checks mapped against the **OWASP Top 10 (2021)** framework, evaluating HTTP headers, URL structure, HTML forms, parameters, transport encryption, cookies, and correlated CVEs without transmitting destructive attack payloads.

> [!IMPORTANT]
> **Safety Boundary & Assessment Philosophy**:
> AlaviTrace performs non-destructive heuristic reconnaissance and controlled observation. It **never** executes active exploitation payloads (e.g., SQLi `' OR 1=1`, command injection `; id`, SSRF metadata exfiltration, or password brute-forcing). Findings represent candidate vulnerabilities and observable attack surfaces requiring manual validation by authorized security personnel.

---

## 2. Detection Architecture

The Phase 7 detection pipeline builds directly on early-stage reconnaissance and passive HTTP enumeration:

```
Target Validation
      ↓
Nmap Network Reconnaissance (-sV)
      ↓
Passive HTTP/HTTPS Enumeration (Headers, HTML, Cookies, Forms)
      ↓
AssessmentContext Assembly
      ↓
CheckRegistry Execution (12 Built-in Checks)
  ├─ A01: Broken Access Control (Directory listing, sensitive paths)
  ├─ A02: Cryptographic Failures (Cleartext HTTP, missing HSTS)
  ├─ A03: Injection Indicators (Heuristic query/form parameter mapping)
  ├─ A04: Insecure Design (Architectural review limitation note)
  ├─ A05: Security Misconfiguration (Missing headers, banner disclosure)
  ├─ A06: Vulnerable Components (Correlated NVD CVEs on web ports)
  ├─ A07: Identification & Auth (Cleartext login, missing HttpOnly)
  ├─ A08: Software & Data Integrity (Missing SRI, Mixed Content)
  ├─ A09: Security Logging & Monitoring (Assessment boundary note)
  ├─ A10: Server-Side Request Forgery (Candidate URL/proxy parameters)
  ├─ CSRF Weaknesses (POST forms lacking anti-CSRF tokens)
  └─ Cookie Security (Secure flag over TLS, SameSite policies)
      ↓
Fingerprint-Based Deduplication & Merging
      ↓
Vulnerability Prioritizer (Scoring & Candidate Ranking)
      ↓
AI-Assisted Security Analysis (Sanitized Evidence Only)
      ↓
Multi-Format Reports (JSON / Markdown / HTML)
```

---

## 3. Detector Specifications & OWASP Top 10 Coverage

| Category | Detector Function | Detection Logic & Evidence | Severity | Confidence | Non-Destructive Boundary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A01:2021** | `detect_broken_access_control` | Detects exposed directory indexing (`Index of /`, directory listings) and sensitive path segments (`/admin`, `/config`, `/.git`). | MEDIUM | OBSERVED | No directory traversal or authentication bypass. |
| **A01:2021** | `detect_csrf_weaknesses` | Inspects HTML `<form method="POST">` for anti-CSRF token input fields. | MEDIUM | POTENTIAL | Static HTML analysis; does not submit forms or bypass tokens. |
| **A02:2021** | `detect_cryptographic_failures` | Identifies cleartext HTTP transport without HTTPS redirection, and missing HSTS on TLS services. | MEDIUM / LOW | CONFIRMED | Inspects initial transport and redirect headers only. |
| **A03:2021** | `detect_injection_indicators` | Maps observed parameters (`id`, `search`, `category`, `cmd`, `sort`) commonly targeted by injection. | LOW | POTENTIAL | No injection payloads or malicious syntax transmitted. |
| **A04:2021** | `detect_insecure_design` | Documents architectural assessment boundaries; avoids false positives on business logic. | INFO | INFORMATIONAL | Informational callout regarding threat modeling needs. |
| **A05:2021** | `detect_security_misconfiguration` | Audits missing security headers (CSP, X-Frame-Options, X-Content-Type-Options) and verbose banners. | MEDIUM / LOW / INFO | CONFIRMED / OBSERVED | Passive header inspection without fuzzing. |
| **A05:2021** | `detect_cookie_security` | Verifies `Secure` attribute over TLS and `SameSite` policy across cookies. | MEDIUM / LOW | CONFIRMED / OBSERVED | Inspects Set-Cookie directives returned by server. |
| **A06:2021** | `detect_vulnerable_components` | Reuses correlated Phase 4 NVD CVEs for web-facing software banners without duplicate API queries. | Varied | PROBABLE / POTENTIAL | Correlated from version banners; no exploit verification. |
| **A07:2021** | `detect_identification_authentication_weakness` | Flags password forms served over cleartext HTTP and cookies missing `HttpOnly`. | HIGH / LOW | CONFIRMED | Passive HTML/cookie inspection; no credentials submitted. |
| **A08:2021** | `detect_software_data_integrity_failures` | Detects external CDN scripts missing Subresource Integrity (SRI) hashes and Mixed Content inclusions. | LOW / MEDIUM | OBSERVED / CONFIRMED | Parses landing page static script and link tags. |
| **A09:2021** | `detect_security_logging_monitoring_gaps` | Documents limitation: external network probes cannot determine internal SOC/logging posture. | INFO | INFORMATIONAL | Informational boundary statement; no false positives. |
| **A10:2021** | `detect_ssrf_indicators` | Heuristically identifies candidate parameters (`url`, `dest`, `redirect`, `webhook`, `fetch`). | LOW | POTENTIAL | No outbound HTTP requests or SSRF probes transmitted. |

---

## 4. Structured Finding Model (`OWASPFinding`)

Every finding produced by the OWASP Detection Engine inherits from the core `Finding` model, ensuring complete backward compatibility:

- **`id`**: Unique identifier (e.g., `OWASP-A01-DIRLIST-1`, `OWASP-A02-CLEARTEXT-1`).
- **`title`**: Descriptive title using standard defensive security terminology (e.g., *"Potential Directory Listing Exposed"*).
- **`owasp_category`**: Full OWASP category string (e.g., `A01:2021 - Broken Access Control`).
- **`severity`**: Core `Severity` enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **`confidence`**: Core `Confidence` enum (`CONFIRMED`, `PROBABLE`, `POTENTIAL`, `OBSERVED`, `INFORMATIONAL`).
- **`endpoint` / `url`**: Specific URL or endpoint where the issue was identified.
- **`evidence`**: Grounded, verifiable factual proof (exact header values, HTML snippet, observed parameters).
- **`description`**: Clear technical explanation of the vulnerability risk.
- **`remediation` / `recommendation`**: Actionable remediation guidance aligned with industry best practices.
- **`limitations`**: Explicit declaration of the assessment boundary and why manual verification is necessary.
- **`references`**: Authoritative references to OWASP Top 10 documentation.

---

## 5. Deduplication & Reconciliation

To prevent redundant alerts (e.g., missing CSP reported during Phase 3 HTTP enumeration and again during Phase 7 OWASP assessment):

1. **Deterministic Fingerprinting**: Findings are normalized into an identity fingerprint:
   $$\text{Fingerprint} = \text{norm\_title} \parallel \text{norm\_endpoint} \parallel \text{norm\_parameter} \parallel \text{norm\_method}$$
2. **Metadata Enrichment**: When an OWASP check produces a finding that matches an existing Phase 3 finding, the existing finding is enriched with `owasp_category`, `detection_type`, and `limitations` rather than creating a duplicate entry.
3. **Internal Suppression**: Subsequent identical findings within the same assessment run are suppressed.

---

## 6. CLI Usage

The OWASP Web Vulnerability Detection Engine is enabled by default whenever reachable HTTP/HTTPS services are detected on the target.

```bash
# Default execution (OWASP assessment automatically runs if HTTP/HTTPS ports are open)
python -m alavitrace.cli -t 192.168.56.106 --pn

# Explicitly enable OWASP assessment
python -m alavitrace.cli -t 192.168.56.106 --pn --owasp

# Explicitly disable OWASP assessment
python -m alavitrace.cli -t 192.168.56.106 --pn --no-owasp
```

When web ports are absent (as with the Sunset target VM `192.168.56.106` which only exposes FTP and SSH), the engine gracefully skips:

```
================================================================
                    OWASP WEB SECURITY                          
================================================================
Target: 192.168.56.106

No HTTP/HTTPS service detected.
OWASP web assessment skipped.
================================================================
```

---

## 7. Reporting Integration

OWASP assessment results are fully represented across all three output formats:

1. **JSON (`reports/*.json`)**:
   - Dedicated `"owasp_assessment"` object containing `is_http_available`, `supported_categories`, `executed_checks`, `findings_count`, and `summary_by_severity` (`critical`, `high`, `medium`, `low`, `informational`).
   - Each finding includes `url`, `remediation`, and `limitations`.
2. **Markdown (`reports/*.md`)**:
   - Dedicated section `## 5. OWASP Web Security Assessment` with severity count summary, disclaimer callout, and Markdown table including the `Limitations` column.
3. **HTML (`reports/*.html`)**:
   - Styled OWASP Web Security Assessment card with severity count badges (`Critical: X`, `High: Y`, `Medium: Z`, `Low: W`, `Info: V`) and table with `Limitations` column.

---

## 8. Safety & AI Guardrails

1. **Gemini Grounding**: The AI Security Analyst layer only receives sanitized, structured finding objects. It cannot invent new vulnerabilities or execute live network actions.
2. **Evidence Grounding**: No finding is generated without direct evidence in the HTTP response (status code, headers, cookie jar, form tags, or correlated NVD CVE).
3. **Non-Intrusive**: No brute force, no payloads, no RCE attempts, and no outbound SSRF connections.
