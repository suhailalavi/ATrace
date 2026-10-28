# OWASP A05:2021 Security Misconfiguration Engine

## 1. Overview & Objectives

**Security Misconfiguration** represents one of the most common and pervasive categories in application and network security. In the **OWASP Top 10 (2021)**, **A05: Security Misconfiguration** covers insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers and verbose error messages containing sensitive information, outdated software configurations, unencrypted legacy protocols, and unnecessary enabled services or features.

In **AlaviTrace Phase 9**, the framework significantly expands deterministic, non-destructive detection of security misconfigurations across both web services and underlying network infrastructure.

> [!IMPORTANT]
> **Defensive & Non-Destructive Principles**:
> All A05 checks in AlaviTrace are deterministic, passive, and non-destructive:
> - **Zero Destructive Fuzzing**: No intrusive fuzzing, brute forcing, or exploitation payloads are transmitted.
> - **Zero Sensitive File Harvesting**: AlaviTrace inspects standard informational paths (`/robots.txt` Disallow directives, `/.well-known/security.txt`). It **never** attempts to harvest credentials or secret files (e.g. `.env`, `.git/config`, `wp-config.php`, or `/etc/passwd`).
> - **False-Positive Prevention**: Generic 500 error pages without internal diagnostic information are never flagged as information disclosure.

---

## 2. Architecture & Check Taxonomy

AlaviTrace detects A05 Security Misconfigurations across 10 deterministic dimensions:

```
Reconnaissance & Enumeration
        ↓
A05 Security Misconfiguration Analyzer
  ├─ A05.1 Missing Security Headers (CSP, nosniff, XFO, HSTS, Referrer, Permissions)
  ├─ A05.2 Verbose Server Banner & Technology Disclosure (Server, X-Powered-By, Framework)
  ├─ A05.3 Directory Listing & Indexing Signatures (Apache, Nginx, IIS index pages)
  ├─ A05.4 Informational Files Disclosure (Sensitive robots.txt Disallow directives)
  ├─ A05.5 HTTP Method Misconfiguration (OPTIONS Allow header parsing, TRACE detection)
  ├─ A05.6 HTTPS & TLS Configuration (Certificate expiration, hostname mismatch, HTTP redirect)
  ├─ A05.7 Cookie Security (Secure flag over TLS, SameSite policies, HttpOnly)
  ├─ A05.8 Verbose Diagnostic Error Disclosure (Python, Java, PHP, ASP.NET, Spring stack traces)
  ├─ A05.9 Debug Mode Exposure (Werkzeug debugger, Django DEBUG, Laravel Ignition, Spring Actuator)
  └─ A05.10 Legacy & Unnecessary Exposed Services (FTP, Telnet, Finger, R-commands)
        ↓
Fingerprint-Based Deduplication (Prevents duplicates between Phase 3 & OWASP findings)
        ↓
Prioritization Engine & Multi-Format Reports (JSON, Markdown, HTML)
```

---

## 3. Detailed Check Specifications

### A05.1 Missing Security Headers
Evaluates HTTP response headers against hardened modern web security baselines:
- **Content-Security-Policy (CSP)** (Severity: MEDIUM, Confidence: CONFIRMED): Detects missing CSP headers that restrict unauthorized script execution and defend against Cross-Site Scripting (XSS).
- **X-Content-Type-Options: nosniff** (Severity: LOW, Confidence: CONFIRMED): Ensures browsers do not MIME-sniff responses away from the declared content-type.
- **X-Frame-Options** (Severity: LOW, Confidence: CONFIRMED): Confirms clickjacking defense via `DENY`, `SAMEORIGIN`, or CSP `frame-ancestors`.
- **Strict-Transport-Security (HSTS)** (Severity: LOW, Confidence: CONFIRMED): Evaluated on HTTPS responses to enforce transport layer encryption.
- **Referrer-Policy** (Severity: INFO, Confidence: CONFIRMED): Governs sensitive referrer URL leakage to external origins.
- **Permissions-Policy** (Severity: INFO, Confidence: CONFIRMED): Verifies restrictions on sensitive client APIs (camera, microphone, geolocation).

### A05.2 Verbose Server Banner & Technology Disclosure
Inspects HTTP responses for granular version disclosure:
- **Server Header**: Flags detailed version numbers (e.g. `Apache/2.4.38 (Debian)`, `nginx/1.14.0`).
- **X-Powered-By Header**: Identifies backend runtime disclosures (e.g. `PHP/7.3.27`, `Express`).
- **Framework Headers**: Discovers application framework signatures (e.g. `X-AspNet-Version`, `X-Generator`).

### A05.3 Directory Listing Signatures
Identifies enabled directory indexing on web servers through signature matching on response body content:
- Signatures: `<title>Index of /`, `<h1>Index of /`, `Directory listing for /`, `[To Parent Directory]`, `Parent Directory</a>`.
- Severity: `MEDIUM`, Confidence: `PROBABLE`.

### A05.4 Informational Files Disclosure (Robots.txt)
Inspects public `/robots.txt` responses for sensitive `Disallow:` directives that reveal internal directory structures to attackers:
- Evaluated sensitive keywords: `/admin`, `/administrator`, `/config`, `/backup`, `/private`, `/secret`, `/db`, `/manage`, `/internal`, `/api-docs`, `/actuator`.
- Severity: `LOW`, Confidence: `CONFIRMED`.

### A05.5 HTTP Method Misconfiguration & TRACE Detection
Analyzes advertised methods from HTTP `OPTIONS` requests and response `Allow` headers:
- **HTTP TRACE Method**: Flags enabled TRACE method (Severity: `MEDIUM`, Confidence: `CONFIRMED`) which facilitates Cross-Site Tracing (XST) credential theft.
- **Risky/Unnecessary Methods**: Identifies advertised `PUT`, `DELETE`, or `CONNECT` methods (Severity: `LOW`, Confidence: `OBSERVED`).

### A05.6 HTTPS & TLS Configuration
Evaluates SSL/TLS transport configurations:
- **Expired Certificate**: Verifies TLS certificate expiration dates (Severity: `HIGH`, Confidence: `CONFIRMED`).
- **Hostname Mismatch**: Detects certificates issued for a different Common Name or Subject Alternative Name (SAN) (Severity: `MEDIUM`, Confidence: `CONFIRMED`).
- **Missing HTTPS Redirection**: Identifies accessible HTTP endpoints when an HTTPS service is also present on the target (Severity: `LOW`, Confidence: `OBSERVED`).

### A05.7 Cookie Security
Audits `Set-Cookie` directives returned by web applications:
- **Missing Secure Flag**: Transmitting cookies over HTTPS without the `Secure` flag permits transmission over unencrypted HTTP (Severity: `MEDIUM`, Confidence: `CONFIRMED`).
- **Missing SameSite Attribute**: Cookies omitting `SameSite=Lax` or `SameSite=Strict` remain susceptible to Cross-Site Request Forgery (Severity: `LOW`, Confidence: `OBSERVED`).
- **Missing HttpOnly Flag**: (Audited under A07) Exposes session identifiers to client-side scripts and XSS theft.

### A05.8 Verbose Diagnostic Error Message Disclosure
Detects detailed runtime exceptions and diagnostic stack traces in response bodies:
- **Python**: `Traceback (most recent call last):`, `File "...", line ..., in ...`.
- **Java**: `Exception in thread "..."`, `\tat com....java:...`, `org.apache.catalina.`, `org.springframework.`.
- **PHP**: `Fatal error: ... in /... on line ...`, `Warning: ... in /... on line ...`.
- **ASP.NET**: `Server Error in '/' Application`, `System.Web.HttpException`.
- **Spring**: `Whitelabel Error Page`, `There was an unexpected error (type=Internal Server Error)`.
- *Note*: Generic 500 error pages (`500 Internal Server Error`) without stack traces are excluded to prevent false positives.

### A05.9 Debug Mode Exposure
Detects framework debug modes left enabled in production:
- **Werkzeug Debugger**: `Werkzeug powered traceback interpreter`, `<div class="debugger">`, `console__icon`.
- **Django DEBUG**: `You're seeing this error because you have DEBUG = True in your settings file`.
- **Laravel Ignition**: `<title>...Ignition</title>`, `flare-app`, `Whoops! There was an error.`.
- **Spring Boot Actuator**: Exposed `/actuator` management endpoints revealing system metrics and environment details.

### A05.10 Legacy & Unnecessary Exposed Services
Audits network reconnaissance results from Nmap for unencrypted, obsolete protocols:
- **FTP (Port 21/tcp)**: Cleartext File Transfer Protocol.
- **Telnet (Port 23/tcp)**: Unencrypted remote terminal protocol.
- **Finger (Port 79/tcp)**: Legacy user information service.
- **R-commands (Ports 512–514/tcp)**: Legacy unencrypted remote execution daemons (`rexec`, `rlogin`, `rsh`).

---

## 4. CLI Usage & Flags

The security misconfiguration engine runs by default when `--owasp` is active (enabled by default when web services are discovered).

```powershell
# Standard run with OWASP assessment enabled
python -m alavitrace.cli --target 192.168.56.106 --pn

# Explicitly request detailed misconfiguration assessment
python -m alavitrace.cli --target 192.168.56.106 --pn --misconfig

# Verbose output with custom top findings limit
python -m alavitrace.cli --target 192.168.56.106 --pn --misconfig --max-findings 10 -v
```

---

## 5. Reporting Structure

Findings identified by the A05 engine are seamlessly integrated into:
1. **CLI Summary**: Grouped into dedicated `[A05] Security Misconfiguration` sections.
2. **JSON Report**: Available in `owasp_assessment.a05_misconfiguration` and root `a05_misconfiguration` nodes.
3. **Markdown Report**: Summarized in `### A05:2021 Security Misconfiguration Summary`.
4. **HTML Report**: Highlighted with interactive badge counts and detailed vulnerability cards.
