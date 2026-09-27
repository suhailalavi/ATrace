# Passive HTTP Enumeration & Recommendation Engine

## Overview

In **ATrace v0.1 (Phase 3)**, passive HTTP/HTTPS enumeration acts as a conditional analysis layer. When Nmap identifies open web services (e.g. ports 80, 443, 8080, 8443), ATrace automatically executes non-intrusive HTTP GET requests to inspect server response headers and security configuration indicators.

ATrace does **not** perform intrusive web attacks, directory brute forcing, or exploitation. All recommendations generated in Phase 3 are **deterministic, reproducible security hardening guidelines** based solely on observed HTTP header configurations.

---

## Architecture & Data Flow

```
[ Nmap Open Ports ] ──(Filter HTTP/HTTPS)──► [ build_http_urls ] ──► [ HttpEnumerator ]
                                                                             │
                                                                             ▼
[ CLI Summary ] ◄── [ Finding Models ] ◄── [ RecommendationEngine ] ◄── [ HttpResult ]
```

---

## What Information is Collected?

- **Response Status**: HTTP status code (e.g. 200, 301, 403, 404) and response latency.
- **Redirect History**: Redirect chain tracking (e.g. HTTP to HTTPS redirection).
- **Server Metadata**: `Server` and `X-Powered-By` headers exposing software versions.
- **Content Metadata**: `Content-Type` and `Content-Length`.
- **Security Headers**: Inspection of 6 key HTTP security headers.

---

## Security Headers Analyzed

| Header Name | Purpose | Risk if Missing |
| :--- | :--- | :--- |
| **`Strict-Transport-Security` (HSTS)** | Enforces HTTPS connections. | Users may be vulnerable to SSL stripping / MITM. |
| **`Content-Security-Policy` (CSP)** | Restricts sources of executable scripts/assets. | Increased exposure to Cross-Site Scripting (XSS). |
| **`X-Content-Type-Options`** | Disables MIME-type sniffing (`nosniff`). | Browsers may execute non-executable files as script/CSS. |
| **`X-Frame-Options`** | Controls framing (`DENY` or `SAMEORIGIN`). | Vulnerable to Clickjacking UI redressing attacks. |
| **`Referrer-Policy`** | Controls referrer information in HTTP headers. | Sensitive URL parameters may leak to external domains. |
| **`Permissions-Policy`** | Restricts browser APIs (camera, geolocation). | Unintended access to hardware features in web context. |

> [!NOTE]
> **Important Disclaimer**: Missing security headers are classified as **LOW** or **INFORMATIONAL** security hardening recommendations. They indicate a missing defense-in-depth control, **not** a confirmed exploitable vulnerability.

---

## Safety Controls & Guardrails

1. **Passive Operations Only**: Uses single HTTP GET requests without aggressive fuzzing or payload injection.
2. **Explicit Timeouts**: Hardened timeout (`10 seconds`) to prevent hangs on unresponsive servers.
3. **Safe Subprocess & Header Limits**: Standard User-Agent (`ATrace-Recon/0.1`), no arbitrary user-supplied headers or methods.
4. **Conditional Execution**: Web enumeration runs **only** if Nmap detects an active HTTP/HTTPS service.

---

## Example CLI Output

```text
================================================================
                     PASSIVE HTTP ENUMERATION                   
================================================================

URL: http://192.168.56.101
  Status Code:   200
  Final URL:     http://192.168.56.101
  Response Time: 14.2 ms
  Server Header: Apache/2.4.41 (Ubuntu)
  X-Powered-By:  PHP/7.4.3
  Content-Type:  text/html; charset=UTF-8

  Security Header Status:
    [-] Strict-Transport-Security: Missing
    [-] Content-Security-Policy: Missing
    [-] X-Content-Type-Options: Missing
    [-] X-Frame-Options: Missing
    [-] Referrer-Policy: Missing
    [-] Permissions-Policy: Missing

================================================================
                 DETERMINISTIC RECOMMENDATIONS                  
================================================================

[LOW] Missing X-Content-Type-Options Header
  Asset:          http://192.168.56.101
  Evidence:       Header 'X-Content-Type-Options' was missing from response at http://192.168.56.101.
  Recommendation: Configure the web server to send 'X-Content-Type-Options: nosniff'.

[LOW] Missing Content-Security-Policy (CSP) Header
  Asset:          http://192.168.56.101
  Evidence:       Header 'Content-Security-Policy' was missing from response at http://192.168.56.101.
  Recommendation: Implement a Content-Security-Policy appropriate for the application.
```
