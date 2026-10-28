# Controlled OWASP A03 Injection Detection (Phase 8)

## 1. Overview & Objectives

**Phase 8** implements the **Controlled OWASP A03 Injection Detection Engine** in **AlaviTrace**, providing active, deterministic, and strictly non-destructive probing for injection vulnerabilities across discovered web applications and HTTP/HTTPS services.

Building directly upon the Phase 6/7 OWASP assessment foundation and Phase 3 passive HTTP enumeration, Phase 8 transitions AlaviTrace from purely observational heuristic mapping to active, controlled vulnerability candidate identification.

> [!IMPORTANT]
> **Non-Destructive Testing Boundary & Safety Principle**:
> AlaviTrace is designed strictly for authorized security assessments and ethical penetration testing. The injection engine **never** transmits destructive payloads, arbitrary shell commands, time-based delays (`SLEEP`), database modifications (`DROP`, `INSERT`, `UPDATE`), or exploit payloads. All checks employ benign syntax delimiters and randomly generated canary tokens to observe behavioral deviations safely.

---

## 2. Injection Testing Architecture

```
Discovered Web Services (HTTP/HTTPS)
        ↓
Passive Enumeration (URLs, Query Strings, Forms, Cookies)
        ↓
Parameter Discovery (InjectionTarget Candidates)
        ↓
Target Filtering & Budget Allocation (Max 20 Requests Default)
        ↓
Controlled Probing Engine (HttpProber)
  ├─ Baseline Request (Normal state & response capture)
  ├─ SQL Injection Probes (Harmless syntax delimiters: ', ", \')
  ├─ Reflected XSS Probes (Alphanumeric canary: ATRACE_CANARY_<hex>)
  └─ Command Injection Heuristic Probes (Harmless benign input)
        ↓
Response Analysis (Differential Analysis)
  ├─ Pre-existing DB Error Differentiation
  ├─ Database Engine Regex Matching (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
  └─ HTML Context Parsing (SCRIPT, ATTRIBUTE, URL, STYLE, TEXT)
        ↓
Normalized Findings (OWASPFinding Model)
        ↓
Deduplication & Prioritization (VulnerabilityPrioritizer)
        ↓
AI-Assisted Security Analysis (Structured Evidence Only)
        ↓
Multi-Format Reporting (JSON, Markdown, HTML)
```

---

## 3. Supported Vulnerability Checks & Detection Logic

### 3.1 SQL Injection Detection (SQLi)
- **Methodology**: Delimiter-based error differential detection.
- **Payloads**:
  - `'` (Single quote syntax perturbation)
  - `"` (Double quote syntax perturbation)
  - `\'` (Escaped single quote syntax perturbation)
- **Error Differential Analysis**: The engine captures a baseline response prior to probing. A candidate finding is flagged **only** if a database syntax error appears in the mutated response that was **absent** from the baseline response. This eliminates false positives caused by pages with pre-existing error messages.
- **Supported Database Engines**:
  - **MySQL / MariaDB**: `you have an error in your sql syntax`, `check the manual that corresponds to your mysql/mariadb server version`
  - **PostgreSQL**: `psqlException`, `syntax error at or near`, `pg_query()`
  - **Microsoft SQL Server**: `unclosed quotation mark after the character string`, `driver.*sql server`
  - **SQLite**: `sqlite3.operationalerror`, `near ".*": syntax error`
  - **Oracle**: `ora-00933`, `ora-01756`, `quoted string not properly terminated`
- **Severity & Confidence**: `HIGH` severity, `PROBABLE` confidence.

### 3.2 Reflected Cross-Site Scripting (XSS)
- **Methodology**: Harmless canary reflection and HTML contextual classification.
- **Canary Generation**: Generates an ephemeral cryptographic token per execution:
  ```
  ATRACE_CANARY_<8-HEX-DIGITS> (e.g., ATRACE_CANARY_4A9B1C2D)
  ```
  Transmitted inside a harmless HTML comment and plaintext payload:
  ```html
  <!--ATRACE_CANARY_4A9B1C2D-->ATRACE_CANARY_4A9B1C2D
  ```
- **Contextual Parsing & Risk Assignment**:
  | HTML Context | Description | Severity | Confidence |
  | :--- | :--- | :--- | :--- |
  | `SCRIPT` | Canary reflected inside inline `<script>` tags | **HIGH** | **PROBABLE** |
  | `ATTRIBUTE` | Canary reflected within tag attributes (e.g., `value="..."`) | **MEDIUM** | **PROBABLE** |
  | `URL` | Canary reflected within `href` or `src` attributes | **MEDIUM** | **PROBABLE** |
  | `STYLE` | Canary reflected inside `<style>` blocks | **MEDIUM** | **POTENTIAL** |
  | `TEXT` | Canary reflected in regular HTML body text | **LOW** | **POTENTIAL** |

### 3.3 Command Injection Heuristic Assessment
- **Methodology**: Identification of high-risk parameter names combined with harmless benign input mutation (`test123`).
- **High-Risk Candidate Parameters**: `cmd`, `exec`, `command`, `run`, `ping`, `query`, `host`, `ip`, `path`, `file`, `dir`, `eval`.
- **Safety Principle**: Does **not** transmit shell metacharacters (`;`, `|`, `&`, `` ` ``, `$()`), path traversal payloads, or reverse shell strings. Identifies parameters requiring prioritization for manual review.
- **Severity & Confidence**: `LOW` severity, `POTENTIAL` confidence.

---

## 4. Safety Controls & Operational Safeguards

To prevent service degradation, lockouts, or unintended side effects, the injection engine enforces strict operational constraints:

1. **Strict Request Budgeting**:
   - Hard default limit of **20 HTTP requests** per scan target.
   - Configurable at the CLI via `--max-injection-requests <count>`.
   - Probing halts immediately once the limit is reached.
2. **Rate Limiting & Delays**:
   - Built-in delay of **100ms** (`0.1s`) between consecutive requests to prevent target load spikes.
3. **HTTP 429 Throttle Backoff**:
   - Automatically detects HTTP `429 Too Many Requests` or WAF rate-limiting responses.
   - Sets a `rate_limited` flag and terminates remaining probes cleanly without error.
4. **Strict HTTP Timeouts**:
   - Enforces a 5-second socket timeout per request to prevent hanging on unresponsive servers.
5. **No Harmful Payloads**:
   - Strictly zero destructive commands (`rm`, `DROP`, `UPDATE`, `format`).
   - Zero sleep/delay payloads (`WAITFOR DELAY`, `pg_sleep`, `sleep`) that could cause thread exhaustion.
   - Zero authentication brute-forcing.

---

## 5. Parameter Discovery Engine

The injection engine discovers attack surface targets dynamically from passive HTTP artifacts:

- **Query Parameters**: Extracted from URL query strings (e.g., `http://target/search.php?q=test&cat=1`).
- **Form Inputs**: Extracted from parsed HTML `<form>` elements (both `GET` and `POST` methods), including text inputs, search fields, and hidden parameters.
- **Deduplication**: Parameters are deduplicated per endpoint and method to prevent redundant testing.

---

## 6. CLI Usage & Flags

### Enabling Injection Assessment
Injection assessment is enabled via the `--injection` flag:

```bash
# Run full assessment including controlled A03 injection testing
python -m alavitrace.cli --target 192.168.56.106 --pn --owasp --injection --format all

# Run injection testing with custom request budget (e.g., 30 requests)
python -m alavitrace.cli --target 192.168.56.106 --pn --owasp --injection --max-injection-requests 30

# Explicitly disable injection testing (default behavior)
python -m alavitrace.cli --target 192.168.56.106 --pn --owasp --no-injection
```

### CLI Output Section
When enabled, the CLI renders a dedicated `A03 INJECTION ASSESSMENT` section in the console output:

```text
======================================================================
  A03 INJECTION ASSESSMENT (CONTROLLED PROBING)
======================================================================
  Targets Tested:     2
  Requests Sent:      8 / 20 budget
  Findings Detected:  1
  Rate Limited:       No

  [HIGH] Potential SQL Injection Indicator (MySQL)
    Endpoint:  http://192.168.56.106/search.php
    Parameter: q (query)
    Evidence:  Baseline response showed no DB error; mutated payload "'" triggered:
               ...You have an error in your SQL syntax; check the manual...
```

---

## 7. Reporting & Data Models

### JSON Report (`scan_results.json`)
The JSON report includes full injection telemetry under `owasp_assessment.a03_injection` and root `a03_injection`:

```json
{
  "a03_injection": {
    "enabled": true,
    "targets_tested": 2,
    "requests_sent": 8,
    "findings_count": 1,
    "rate_limited": false,
    "errors": []
  }
}
```

### Markdown Report (`scan_results.md`)
Includes the `### A03:2021 Injection Assessment Summary` table listing tested endpoints, parameters, probe types, and detected candidate indicators.

### HTML Report (`scan_results.html`)
Features an **A03 Injection Candidates** badge and evidence blocks displaying baseline vs. mutated diffs and contextual reflection snippets.

---

## 8. Limitations & Manual Verification Guide

> [!WARNING]
> **Manual Validation Requirement**:
> Findings generated by the A03 injection engine represent **potential vulnerabilities and observed indicators**, not confirmed exploits.

- **False Positive Elimination**: While differential analysis eliminates pre-existing errors, web applications that reflect user input into customized non-SQL error messages may trigger potential flags. Always manually verify with authorized tools (e.g., SQLMap with `--technique=E` in a lab setting).
- **DOM-Based XSS**: The engine inspects server-side HTTP response bodies. Client-side DOM XSS executed purely by JavaScript cannot be observed without a headless browser runtime.
- **Blind Injection**: Blind SQL injection (boolean or time-based) and blind OS command injection are intentionally excluded from active automated probing to prevent denial of service and extensive request counts.
