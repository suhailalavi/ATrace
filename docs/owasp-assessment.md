# OWASP Web Security Assessment Engine (Phase 6 Foundation)

## 1. Purpose

The **OWASP Web Security Assessment Engine** in **AlaviTrace** provides a modular, extensible, and evidence-grounded architecture for evaluating web applications against the **OWASP Top 10 (2021)** security risks.

> [!IMPORTANT]
> **Phase 6 Scope Boundary**: Phase 6 establishes the foundational framework, data models, check registry, and reporting integration. Individual vulnerability detection modules (e.g., active injection probes, cryptographic checks, SSRF) are implemented in subsequent phases (Phase 7–10). Phase 6 does **not** claim full OWASP Top 10 automated detection.

---

## 2. Core Architecture & Separation of Concerns

AlaviTrace strictly separates **detection**, **evidence collection**, **finding generation**, **prioritization**, and **AI explanation**:

```
Target
  │
  ▼
Target Validation (Phase 1)
  │
  ▼
Network Reconnaissance & Services (Phase 2 - Nmap)
  │
  ▼
Passive HTTP Enumeration (Phase 3)
  │
  ▼
OWASP Assessment Engine (Phase 6)
  ├─ Check Registry & Execution
  ├─ Fingerprint-Based Deduplication
  └─ Evidence-Grounded OWASPFinding Generation
  │
  ▼
Vulnerability Intelligence (Phase 4 - NVD Correlation)
  │
  ▼
Deterministic Prioritization (Phase 4.1)
  │
  ▼
AI-Assisted Security Analysis (Phase 5 - Gemini Contextualization)
  │
  ▼
Multi-Format Reporting (JSON / Markdown / HTML)
```

**Guardrail**: The AI analysis layer (Gemini) does **not** detect vulnerabilities, invent endpoints, generate attack payloads, or claim confirmed exploitability. It operates strictly as an explanatory and contextualization layer over verified evidence.

---

## 3. OWASP Category Model

AlaviTrace models the full OWASP Top 10 (2021) standard, explicitly tracking support readiness:

| Category Code | Name | Support Status | Phase Roadmap |
| :--- | :--- | :--- | :--- |
| **A01:2021** | Broken Access Control | **Supported** | Phase 9 |
| **A02:2021** | Cryptographic Failures | **Supported** | Phase 7 |
| **A03:2021** | Injection | **Supported** | Phase 8 |
| **A04:2021** | Insecure Design | **Limited / Future** | Roadmap |
| **A05:2021** | Security Misconfiguration | **Supported** | Phase 3 (Headers) / Phase 7 |
| **A06:2021** | Vulnerable and Outdated Components | **Supported** | Phase 4 (NVD) / Phase 11 |
| **A07:2021** | Identification and Authentication Failures | **Supported** | Phase 9 |
| **A08:2021** | Software and Data Integrity Failures | **Limited / Future** | Roadmap |
| **A09:2021** | Security Logging and Monitoring Failures | **Limited / Future** | Roadmap |
| **A10:2021** | Server-Side Request Forgery (SSRF) | **Supported** | Phase 10 |

The engine tracks support status through `CategorySupportStatus.SUPPORTED` and `CategorySupportStatus.LIMITED`. It will **never** generate fabricated findings for unsupported categories.

---

## 4. Assessment Context (`AssessmentContext`)

Checks do not execute network tools or scanners directly. Instead, they receive an immutable `AssessmentContext` populated with evidence already collected by upstream reconnaissance:

- `target`: Normalized `Target` specification.
- `scan_result`: Parsed Nmap `ScanResult` including hosts, open ports, service versions, and CPEs.
- `http_results`: Discovered HTTP responses, status codes, headers, and latency metrics.
- `existing_findings`: Prior findings (such as Phase 3 HTTP security recommendations).
- `options`: Execution parameters such as `--max-findings`.

### HTTP Availability Guard
The engine evaluates `context.has_http_service()`. If no web ports (e.g., 80, 443, 8080) or HTTP services exist on the target:
```
================================================================
                    OWASP WEB ASSESSMENT                        
================================================================
Target: 192.168.56.106

No HTTP/HTTPS service detected.
OWASP web assessment skipped.
================================================================
```
No false or artificial web findings are produced.

---

## 5. Check Interface (`BaseAssessmentCheck`)

All OWASP assessment checks implement the `BaseAssessmentCheck` abstract base class:

```python
class BaseAssessmentCheck(ABC):
    category: OwaspCategory
    name: str
    description: str
    detection_type: DetectionType

    @abstractmethod
    def check(self, context: AssessmentContext) -> List[OWASPFinding]:
        """Executes check against context and returns zero or more findings."""
        pass
```

Checks are decoupled from CLI and output logic, enabling full offline unit testability.

---

## 6. Check Registry (`CheckRegistry`)

The `CheckRegistry` allows checks to be registered, queried, and retrieved dynamically:

```python
from alavitrace.assessment.registry import CheckRegistry, default_registry

registry = CheckRegistry()
registry.register(my_check_instance)
checks = registry.get_by_category(OwaspCategory.A05_2021)
```

### Future Check Stubs
Phase 6 defines placeholder check classes for subsequent phases:
- `AccessControlCheckStub` (A01)
- `CryptographicFailuresCheckStub` (A02)
- `InjectionCheckStub` (A03)
- `SecurityMisconfigurationCheckStub` (A05)
- `VulnerableComponentsCheckStub` (A06)
- `AuthenticationCheckStub` (A07)
- `SSRFCheckStub` (A10)

These stubs safely return empty finding sets until implemented in their dedicated phases.

---

## 7. Finding Model (`OWASPFinding`)

`OWASPFinding` extends the core `Finding` dataclass to ensure 100% backward compatibility across prioritizers, reporters, and AI models while providing OWASP-specific metadata:

- `owasp_category`: Full category name (e.g., `"A05:2021 - Security Misconfiguration"`).
- `endpoint`: Affected web URL (e.g., `"http://192.168.56.106/"`).
- `http_method`: HTTP request method (e.g., `"GET"`).
- `parameter`: Specific vulnerable parameter (or `None`).
- `detection_type`: How the finding was identified (`passive`, `active`, or `correlated`).

---

## 8. Confidence Model

Phase 6 defines strict confidence conventions:
- `Confidence.OBSERVED`: A security property or absence is directly observable (e.g., missing security header).
- `Confidence.POTENTIAL`: A condition suggests potential weakness without confirmed exploitability.
- `Confidence.PROBABLE`: Multiple deterministic factors strongly support the finding (e.g., exact CPE match).
- `Confidence.CONFIRMED`: **Reserved** for future verified manual validation or controlled exploit confirmation. Automated Phase 6 checks do not assert `CONFIRMED`.

---

## 9. Detection Types

Findings record their methodology:
- `passive`: Observation of headers, status codes, and non-intrusive metadata.
- `active`: Controlled test requests or non-destructive probes (Phases 7–10).
- `correlated`: Direct mapping from NVD/CVE vulnerability intelligence (Phase 4 / A06).

---

## 10. Deduplication & Identity Fingerprints

To prevent duplicate findings between Phase 3 (Reconnaissance Recommendations) and Phase 6 (OWASP Assessment), the engine calculates normalized fingerprints:

$$\text{Fingerprint} = \text{NormalizedTitle} \mid \text{NormalizedEndpoint} \mid \text{Parameter} \mid \text{Method}$$

When an OWASP finding matches an existing Phase 3 finding (e.g., `Missing Content-Security-Policy`), the engine enriches the existing finding with OWASP metadata rather than creating a duplicate finding in the report.

---

## 11. Prioritization Integration

OWASP findings are seamlessly processed by the Phase 4.1 `VulnerabilityPrioritizer`:
- Scored via: $\text{Severity} + \text{Confidence} + (\text{CVSS} \times 10) + \text{Exposure}$.
- When an OWASP finding has no CVSS score, CVSS defaults to `0.0` (points = 0). **No artificial CVSS scores are fabricated.**
- Exposed endpoints receive standard exposure weights (+20 pts).

---

## 12. CLI Usage

To enable the OWASP assessment engine:

```bash
# Standard reconnaissance + OWASP assessment
python -m alavitrace.cli --target 192.168.56.106 --pn --owasp

# With custom findings limit and multi-format reporting
python -m alavitrace.cli --target 192.168.56.106 --pn --owasp --max-findings 5 --format all
```

When `--owasp` is omitted, AlaviTrace runs the baseline Phase 1–5 pipeline without alteration.

---

## 13. Reporting Integration

- **JSON (`reports/*.json`)**: Contains `"owasp_assessment"` with `is_http_available`, `supported_categories`, `executed_checks`, and structured finding records.
- **Markdown (`reports/*.md`)**: Features `## 5. OWASP Web Security Assessment` table or skip notice.
- **HTML (`reports/*.html`)**: Styled assessment card displaying findings with category badges, endpoints, and evidence.

---

## 14. Gemini AI Integration

The AI analyst receives sanitized, evidence-bound OWASP assessment metadata:
- Summarizes attack surface context.
- Explains remediation priorities.
- Never invents vulnerabilities, parameters, or endpoints.

---

## 15. Safety Boundaries

AlaviTrace is an educational, defensive, and authorized assessment framework:
- No credential brute-forcing.
- No denial-of-service activity.
- No arbitrary exploitation or command injection.
- Strict authorization warnings enforced on startup.
