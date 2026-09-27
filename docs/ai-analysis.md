# AI-Assisted Security Analysis

## Overview

In **ATrace v0.1 (Phase 5)**, the AI Security Analysis layer synthesizes, explains, and prioritizes technical findings collected during automated reconnaissance and vulnerability correlation.

The AI component operates **strictly as an explanation, summarization, and investigation guidance engine**. It does **not** perform autonomous scanning, command execution, or vulnerability exploitation.

---

## Architectural Principles & Boundaries

```
[ Deterministic Scanners & CVE Intelligence ]
                      │
                      ▼ (Raw Evidence)
         [ Structured JSON Serialization ]
                      │
                      ▼ (Sanitized Evidence)
          [ Gemini AI Analysis Provider ]
                      │
                      ▼ (Structured Analysis)
  [ Unified Assessment Report (JSON / MD / HTML) ]
```

### Truth and Evidence Boundaries
1. **Evidence-Grounded Only**: The AI receives structured JSON representing observed ports, services, HTTP metadata, and correlated CVE records. It is instructed to operate strictly on the supplied JSON and never invent hostnames, open ports, versions, or CVE IDs.
2. **Exploitation Guardrail**: The AI is prohibited from asserting that a target is "confirmed vulnerable" or "exploited". Findings are presented as potential vulnerability matches requiring manual verification.
3. **No Executable Shell Commands**: The AI output is strictly informational. It does not generate shell commands, terminal attack payloads, or automated exploit scripts for execution.
4. **Prompt Injection Defense**: All values inside the input JSON (such as server headers or CVE descriptions) are treated as **untrusted data**. Prompt templates include explicit instructions to ignore embedded instructions (e.g., "ignore previous instructions") if present in scanned text.

---

## AI Input & Privacy Controls

Before sending evidence to the Google Gemini API (`gemini-2.5-flash`), ATrace serializes the data into a compact, sanitized JSON structure.

### What is Included:
- Target address (IPv4 / Hostname)
- Discovered open ports, services, products, versions, and CPEs
- HTTP metadata (status code, latency, server header, missing security headers)
- Correlated CVE identifiers, CVSS scores, descriptions, and recommendations

### What is Excluded:
- Passwords, credentials, cookies, and authorization headers
- Raw Nmap XML and full HTTP response bodies
- API keys (`GEMINI_API_KEY`, `NVD_API_KEY`)

---

## Provider Abstraction & API Configuration

ATrace defines an abstract `AIProvider` base class, allowing seamless substitution of AI models or local LLM runtimes:

```python
class AIProvider(ABC):
    @abstractmethod
    def analyze_security_data(self, structured_input: Dict[str, Any]) -> AIAnalysisResult:
        pass
```

### API Key Configuration
- The `GeminiAIProvider` checks for the `GEMINI_API_KEY` environment variable.
- **Graceful Fallback**: If `GEMINI_API_KEY` is missing or the API call fails/times out, ATrace logs a clear notification (`"AI Analysis Status: GEMINI_API_KEY environment variable not configured."`) and continues to render the complete deterministic assessment report.
