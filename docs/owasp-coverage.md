# AlaviTrace OWASP Top 10 (2021) Coverage Specification (v1.0.0)

AlaviTrace provides honest, transparent accounting of its automated detection and validation capabilities across the OWASP Top 10 (2021) taxonomy.

External black-box scanning has inherent technical boundaries. AlaviTrace clearly distinguishes between categories that can be empirically assessed versus those requiring architectural design review or white-box source code auditing.

---

## OWASP Top 10 (2021) Summary Matrix

| Category | Category Name | Support Level | Primary Assessment Mechanism |
| :--- | :--- | :--- | :--- |
| **A01:2021** | Broken Access Control | **Supported** | Directory listing, sensitive files (.git, .env), robots.txt disallowed paths, CSRF form token absence, path traversal validation |
| **A02:2021** | Cryptographic Failures | **Supported** | TLS certificate validation, expiration tracking, cleartext HTTP service identification, unencrypted sensitive cookie transmission |
| **A03:2021** | Injection | **Supported** | Deterministic SQL error pattern detection, reflected XSS parameter canary probes, command injection reflection analysis |
| **A04:2021** | Insecure Design | **Architectural Review** | Threat modeling and design review required; cannot be detected via external black-box scanning |
| **A05:2021** | Security Misconfiguration | **Supported** | Missing security headers (HSTS, CSP, X-Frame-Options, etc.), default welcome banners, verbose server headers, insecure HTTP methods |
| **A06:2021** | Vulnerable and Outdated Components | **Supported** | Service banner extraction, CPE parsing, NVD CVE database matching, CVSS scoring |
| **A07:2021** | Identification and Authentication Failures | **Supported** | Weak cookie attributes (missing HttpOnly, Secure, SameSite), session tokens in URLs, cleartext basic authentication |
| **A08:2021** | Software and Data Integrity Failures | **Architectural Review** | Subresource Integrity (SRI) inspection; CI/CD pipeline and deserialization auditing require internal access |
| **A09:2021** | Security Logging and Monitoring Failures | **Architectural Review** | Internal SIEM, audit log policies, and alerting mechanisms are internal properties invisible to external scanning |
| **A10:2021** | Server-Side Request Forgery (SSRF) | **Supported** | Identification of URL/destination-accepting query parameters, open redirect indicators |

---

## Detailed Category Capabilities & Boundaries

### A01:2021 – Broken Access Control (Supported)
- **Capabilities**: Detects enabled web directory indexing, crawls for sensitive exposure endpoints (`.git/`, `.env`, `backup.zip`, `/admin/`), extracts disallowed paths from `robots.txt`, identifies HTML forms performing state-changing actions without anti-CSRF tokens, and evaluates path traversal parameter vulnerabilities.
- **Boundaries**: Cannot test multi-tenant data isolation, vertical role elevation, or IDOR without multi-role authenticated test accounts.

### A02:2021 – Cryptographic Failures (Supported)
- **Capabilities**: Checks TLS certificate validity, issuer information, subject alternative names, expiration thresholds, cleartext HTTP usage, and flags cookies transmitted over unencrypted HTTP without the `Secure` attribute.
- **Boundaries**: Internal cryptographic algorithms, key lifecycle management, and application-level encryption cannot be inspected externally.

### A03:2021 – Injection (Supported)
- **Capabilities**: Probes web parameters using non-destructive canary tokens to detect unencoded reflection into HTML body contexts, matches multi-engine SQL syntax error signatures, and detects shell metacharacter reflection.
- **Boundaries**: Out-of-band injection, destructive injection, second-order injection, and time-blind blind injection are out of scope to preserve target integrity.

### A04:2021 – Insecure Design (Architectural Review)
- **Boundaries**: Insecure design reflects fundamental flaws in architecture, business logic, and threat models. Automated external scanners cannot determine if business requirements have inherently insecure designs. Requires formal threat modeling and architectural review.

### A05:2021 – Security Misconfiguration (Supported)
- **Capabilities**: Audits missing defensive HTTP headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), identifies default web server banners, and enumerates potentially dangerous HTTP methods (e.g. `TRACE`, `PUT`, `DELETE`, `OPTIONS`).
- **Boundaries**: Internal server configuration files, cloud IAM permissions, and container runtime settings cannot be accessed from network probes.

### A06:2021 – Vulnerable and Outdated Components (Supported)
- **Capabilities**: Extracts CPE strings from Nmap service banners, correlates components against NVD CVE API v2, assigns CVSS metrics, and calculates deterministic priority rankings.
- **Boundaries**: Obfuscated or backported banners may result in version mismatches; client-side libraries and internal package dependencies require SBOM or software composition analysis (SCA).

### A07:2021 – Identification and Authentication Failures (Supported)
- **Capabilities**: Audits cookie security flags (`HttpOnly`, `SameSite`, `Secure`), identifies session tokens exposed in URLs, and flags basic HTTP authentication over cleartext channels.
- **Boundaries**: Automated password spraying, credential brute-forcing, and multi-factor authentication bypass testing are strictly prohibited.

### A08:2021 – Software and Data Integrity Failures (Architectural Review)
- **Capabilities**: Checks for external script resources loaded without Subresource Integrity (SRI) hashes.
- **Boundaries**: Verifying CI/CD pipelines, code signing, auto-update integrity, and object deserialization requires internal repository and runtime access.

### A09:2021 – Security Logging and Monitoring Failures (Architectural Review)
- **Boundaries**: Logging policies, SIEM integration, log tampering defenses, and alerting thresholds are internal system properties invisible to external scanning.

### A10:2021 – Server-Side Request Forgery (SSRF) (Supported)
- **Capabilities**: Discovers candidate parameters accepting URLs or file paths (`url`, `dest`, `redirect`, `path`, `callback`) and flags open redirection behaviors.
- **Boundaries**: Internal cloud metadata access (`http://169.254.169.254/`) and internal port scanning via SSRF are not executed to avoid unintended intranet impact.
