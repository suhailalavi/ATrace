# Controlled Finding Validation Framework (Phase 9)

## 1. Overview & Objective

The **Controlled Finding Validation Framework** is a deterministic, non-destructive verification layer in AlaviTrace. Its purpose is to consume prioritized candidate findings and gather fresh technical evidence to confirm or refute observed conditions before presenting them to analysts, AI reasoning layers, or executive stakeholders.

Crucially, AlaviTrace maintains a strict separation of concerns:
```
Target Validation
       ↓
Nmap Reconnaissance & Parsing
       ↓
Passive HTTP Enumeration
       ↓
OWASP Web Security Assessment
       ↓
Vulnerability Intelligence (NVD CVE Correlation)
       ↓
Vulnerability Prioritization & Deduplication (Top-N Candidates)
       ↓
Controlled Finding Validation (Phase 9)
       ↓
AI-Assisted Security Analysis (Gemini Explanation)
       ↓
Multi-Format Reporting (JSON / Markdown / HTML)
```

**Architectural Principle:** Deterministic validation engines collect and evaluate empirical evidence. The AI layer (Gemini) explains the evidence and guides investigation, but **never** acts as an autonomous vulnerability validator or exploit author.

---

## 2. Validation Status Semantics

Every validated candidate receives one of five standardized `ValidationStatus` values:

| Status | Definition | Example Scenario |
| :--- | :--- | :--- |
| `VALIDATED` | Deterministic evidence confirmed the condition still holds on fresh testing. | Missing `Strict-Transport-Security` header re-tested and confirmed absent; benign alphanumeric canary safely reflected in response body; target port remains open and reachable. |
| `NOT_VALIDATED` | Target responded, but the expected vulnerability condition was **not** observed. | A reported missing header is now present in the fresh HTTP response; benign canary was sanitised/not reflected; service port closed. |
| `INCONCLUSIVE` | The target was unreachable, timed out, returned WAF/rate limits, or produced ambiguous results. | Request timed out during re-test; connection reset; network unreachable. |
| `NOT_APPLICABLE` | The finding cannot be validated safely via non-destructive automated methods. | Remote Code Execution CVE lacking safe non-destructive checks; target host out of scope. |
| `ERROR` | An unexpected internal error or exception occurred during validation. | Unhandled socket or parsing exception. |

---

## 3. Modular Architecture

The framework is implemented under `alavitrace/validation/`:

- `models.py`: Defines `ValidationStatus` enum and `ValidationResult` dataclass with full serialization.
- `base.py`: Defines `BaseValidator` abstract interface and safety constants (`DEFAULT_VALIDATION_TIMEOUT = 5`, `DEFAULT_MAX_VALIDATION_REQUESTS = 10`, `DEFAULT_VALIDATION_USER_AGENT`).
- `validators.py`: Implements concrete, non-destructive validators:
  - **`HeaderValidator`**: Validates missing security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) by executing a fresh GET request.
  - **`ResponseBehaviorValidator`**: Verifies observable HTTP status codes and response page behaviors against expected findings.
  - **`ReflectedInputValidator`**: Tests parameter reflection using a safe, non-executable alphanumeric canary token (`atracecanary987`). Strictly zero XSS payloads, zero quotes, and zero script tags.
  - **`MisconfigurationValidator`**: Verifies observable misconfigurations such as directory listing signatures (`Index of /`), exposed server banners, or accepted HTTP `TRACE` methods.
  - **`ServicePresenceValidator`**: Verifies whether the affected TCP port is open and reachable for correlated CVEs via non-intrusive TCP socket handshake (`connect_ex`). Strictly zero exploit payloads.
  - **`FallbackValidator`**: Catches unhandled finding categories and assigns `NOT_APPLICABLE`.
- `registry.py`: `ValidatorRegistry` manages validator precedence order and dispatches candidate findings to the appropriate validator.
- `engine.py`: `ValidationEngine` orchestrates validation over candidate findings, enforces target scope boundaries, monitors timeouts, and aggregates metrics into `ValidationEngineResult`.

---

## 4. Strict Safety Guardrails

The validation framework strictly adheres to non-destructive testing principles:

1. **Target Scope Boundary**: Validates only target assets explicitly authorized via the CLI (`-t` / `--target`). Prevents outbound probing against redirected third-party domains or off-scope hosts.
2. **Zero Exploitation**: Never transmits exploit payloads, shellcode, SQL syntax breakers, or credential attacks.
3. **Top-N Scoping**: Validates only top prioritized candidate findings (governed by `--max-findings`, default: 5) to minimize network overhead.
4. **Timeouts & Rate Limiting**: Enforces strict request timeouts (`5s` default) and request budgets (`10` requests max per candidate).
5. **AI Guardrail**: AI analysis models (Gemini) receive structured validation outcomes and are explicitly constrained by system prompts from overriding `NOT_VALIDATED`, `INCONCLUSIVE`, or `NOT_APPLICABLE` findings into confirmed vulnerabilities.

---

## 5. CLI Usage

Finding validation is optional and disabled by default. Enable it using `--validate`:

```bash
# Run full assessment with controlled finding validation
python -m alavitrace.cli -t 192.168.56.106 --pn --validate --format all

# Configure custom validation timeouts and request budgets
python -m alavitrace.cli -t 192.168.56.106 --pn --validate --validation-timeout 3 --max-validation-requests 5

# Combine with OWASP Web Assessment and Prioritization
python -m alavitrace.cli -t 192.168.56.106 --pn --owasp --validate --max-findings 5 --format all
```

---

## 6. Report Integration

Validation outcomes are seamlessly integrated into all report formats:

- **JSON Report (`alavitrace_*.json`)**:
  - Each finding includes a `"validation"` object with status, method, evidence, and error message.
  - Root object includes `"validation_summary"` containing total candidates and per-status breakdown counts.
- **Markdown Report (`alavitrace_*.md`)**:
  - Includes a dedicated `### Controlled Finding Validation Summary (Phase 9)` table.
  - Each finding detail section displays `- **Validation Status:** [STATUS] (Method)` and `- **Validation Evidence:**`.
- **HTML Report (`alavitrace_*.html`)**:
  - Features color-coded status badges (`badge-VALIDATED` green, `badge-NOT_VALIDATED` gray, `badge-INCONCLUSIVE` amber, `badge-NOT_APPLICABLE` slate, `badge-ERROR` red).
  - Prioritized findings table includes a dedicated `Validation Status` column with validation method subtitles.
