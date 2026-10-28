import re
import logging
from typing import List, Dict, Set, Optional, Any

from alavitrace.core.models import Severity, Confidence, Finding, HttpResult
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)

logger = logging.getLogger("AlaviTrace")

# Common sensitive paths and indicators for A01
SENSITIVE_PATHS = [
    "/.git", "/.env", "/config", "/admin", "/administrator",
    "/phpmyadmin", "/dashboard", "/actuator", "/api-docs", "/swagger"
]

DIRECTORY_LISTING_INDICATORS = [
    "<title>index of /", "directory listing for", "[to parent directory]", "index of /"
]

# Candidate parameters for A03 Injection
INJECTION_CANDIDATE_PARAMS = {
    "id", "user_id", "uid", "item", "category", "cat", "search", "q", "query",
    "filter", "sort", "order", "cmd", "exec", "file", "path", "page", "view",
    "dir", "action", "table", "select", "type"
}

# Candidate parameters for A10 SSRF
SSRF_CANDIDATE_PARAMS = {
    "url", "uri", "dest", "destination", "redirect", "redirect_url", "target",
    "link", "src", "fetch", "proxy", "webhook", "feed", "host", "domain",
    "service", "endpoint", "callback", "relay"
}

def detect_broken_access_control(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A01:2021 - Broken Access Control.
    Deterministically inspects directory listing disclosures, sensitive exposed paths,
    and access-control boundary indicators without executing unauthorized actions.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url

        # 1. Directory Listing Check
        if res.body_sample:
            body_lower = res.body_sample.lower()
            if any(ind in body_lower for ind in DIRECTORY_LISTING_INDICATORS):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A01-DIRLIST-{idx}",
                    title="Potential Directory Listing Exposed",
                    owasp_category=OwaspCategory.A01_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.OBSERVED,
                    description=(
                        "The web server appears to have directory browsing enabled, exposing directory contents "
                        "and file structures to unauthenticated users."
                    ),
                    evidence="Response body contains directory index indicators (e.g. 'Index of /' or parent directory link).",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Disable directory indexing in the web server configuration (e.g., 'Options -Indexes' in Apache or 'autoindex off' in Nginx).",
                    limitations="Passive inspection of landing page. Does not traverse directory trees or attempt unauthorized resource retrieval.",
                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                ))
                idx += 1

        # 2. Sensitive Path Exposure (from redirect chain or final URL)
        urls_to_check = [res.url] + res.redirect_chain
        for u in urls_to_check:
            u_lower = u.lower()
            for sp in SENSITIVE_PATHS:
                if sp in u_lower:
                    findings.append(OWASPFinding.create(
                        id=f"OWASP-A01-SENSITIVE-PATH-{idx}",
                        title=f"Potential Sensitive Management Path Disclosed ({sp})",
                        owasp_category=OwaspCategory.A01_2021.value,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.OBSERVED,
                        description=f"Observed URL path includes administrative or configuration prefix '{sp}'.",
                        evidence=f"Target URL path or redirect chain exposes sensitive path segment: {u}",
                        affected_asset=res.url,
                        endpoint=u,
                        http_method="GET",
                        detection_type=DetectionType.PASSIVE.value,
                        recommendation="Restrict administrative interfaces behind role-based authentication, IP allowlists, or internal networks.",
                        limitations="Passive identification from observed URL/redirect; authentication bypass was not attempted.",
                        references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"]
                    ))
                    idx += 1
                    break

    return findings

def detect_cryptographic_failures(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A02:2021 - Cryptographic Failures.
    Evaluates cleartext HTTP usage, missing HSTS over TLS, and unencrypted transmission risks.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url
        is_cleartext = res.url.lower().startswith("http://")
        redirects_to_https = any(r.lower().startswith("https://") for r in res.redirect_chain)

        # 1. Cleartext HTTP without HTTPS redirection
        if is_cleartext and not redirects_to_https:
            findings.append(OWASPFinding.create(
                id=f"OWASP-A02-CLEARTEXT-{idx}",
                title="Cleartext HTTP Transmission Without Enforced Encryption",
                owasp_category=OwaspCategory.A02_2021.value,
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                description=(
                    "The service communicates over plain HTTP without redirecting to HTTPS, allowing network "
                    "eavesdropping and man-in-the-middle data interception."
                ),
                evidence=f"Endpoint {res.url} responded over cleartext HTTP with status {res.status_code} without redirecting to HTTPS.",
                affected_asset=res.url,
                endpoint=endpoint_url,
                http_method="GET",
                detection_type=DetectionType.PASSIVE.value,
                recommendation="Enforce TLS 1.2+ across all web endpoints and configure immediate 301/308 redirects from HTTP to HTTPS.",
                limitations="Evaluates initial transport scheme and redirect policy. In-depth TLS cipher suite testing requires dedicated handshake auditing.",
                references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
            ))
            idx += 1

        # 2. Missing HSTS over HTTPS
        if res.url.lower().startswith("https://") or endpoint_url.lower().startswith("https://"):
            if "Strict-Transport-Security" in res.missing_security_headers:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A02-HSTS-{idx}",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    owasp_category=OwaspCategory.A02_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "The application uses HTTPS but omits the Strict-Transport-Security header, leaving users "
                        "vulnerable to protocol downgrade attacks."
                    ),
                    evidence="Strict-Transport-Security header was not returned in the HTTPS response.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Implement 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server responses.",
                    limitations="Browser HSTS preload list status was not queried.",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"]
                ))
                idx += 1

    return findings

def detect_injection_indicators(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A03:2021 - Injection.
    Heuristically identifies attack surface parameters commonly associated with data queries
    without transmitting injection payloads.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url
        observed = [p.lower() for p in res.observed_parameters]
        matched = [p for p in observed if p in INJECTION_CANDIDATE_PARAMS]

        if matched:
            param_list_str = ", ".join(sorted(matched))
            findings.append(OWASPFinding.create(
                id=f"OWASP-A03-INJ-PARAM-{idx}",
                title="Potential Injection Attack Surface (Observed Input Parameters)",
                owasp_category=OwaspCategory.A03_2021.value,
                severity=Severity.LOW,
                confidence=Confidence.POTENTIAL,
                description=(
                    "The application exposes input parameters commonly associated with dynamic data retrieval, "
                    "database queries, or command processing. Improperly sanitized inputs may lead to injection."
                ),
                evidence=f"Observed parameter(s) [{param_list_str}] on endpoint {endpoint_url}.",
                affected_asset=res.url,
                endpoint=endpoint_url,
                http_method="GET",
                parameter=param_list_str,
                detection_type=DetectionType.PASSIVE.value,
                recommendation="Ensure all input parameters are processed through parameterized queries, ORMs, or strict allowlists. Never concatenate user input directly into executable queries.",
                limitations="Heuristic parameter identification only. No active injection payloads (SQLi, command injection, XSS) were sent. Requires manual validation.",
                references=["https://owasp.org/Top10/A03_2021-Injection/"]
            ))
            idx += 1

    return findings

def detect_insecure_design(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A04:2021 - Insecure Design.
    Documents structural assessment boundaries with zero false positives.
    """
    findings: List[OWASPFinding] = []
    # If HTTP services are available, provide architectural guidance finding
    web_urls = context.get_web_urls()
    if web_urls:
        findings.append(OWASPFinding.create(
            id="OWASP-A04-DESIGN-NOTE-1",
            title="Insecure Design Assessment Limitation",
            owasp_category=OwaspCategory.A04_2021.value,
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description=(
                "OWASP A04:2021 Insecure Design represents flaws in architectural design and missing business logic "
                "controls that cannot be reliably inferred from external network response inspection alone."
            ),
            evidence="External network reconnaissance cannot evaluate threat models or business logic architecture.",
            affected_asset=web_urls[0],
            endpoint=web_urls[0],
            detection_type=DetectionType.PASSIVE.value,
            recommendation="Perform formal threat modeling, secure design reviews, and business logic validation during development.",
            limitations="Automated network scanning cannot determine design-level flaws without application business logic context.",
            references=["https://owasp.org/Top10/A04_2021-Insecure_Design/"]
        ))
    return findings

from alavitrace.analysis.misconfiguration import (
    check_directory_listing,
    check_verbose_error_disclosure,
    check_debug_mode_exposure,
    check_http_methods,
    check_legacy_services
)

def detect_security_misconfiguration(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A05:2021 - Security Misconfiguration.
    Identifies missing standard security headers, verbose server banner disclosures,
    directory listings, diagnostic error disclosures, debug mode indicators,
    unnecessary HTTP methods / TRACE, HTTPS certificate flaws, and exposed legacy services.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    header_specs = [
        (
            "Content-Security-Policy",
            "Missing Content-Security-Policy (CSP) Header",
            Severity.MEDIUM,
            "Helps prevent Cross-Site Scripting (XSS) and data injection attacks by restricting sources of executable content.",
            "Define a restrictive Content-Security-Policy (CSP) specifying trusted script and resource sources."
        ),
        (
            "X-Content-Type-Options",
            "Missing X-Content-Type-Options Header",
            Severity.LOW,
            "Prevents web browsers from MIME-sniffing a response away from the declared Content-Type.",
            "Set 'X-Content-Type-Options: nosniff' across all HTTP responses."
        ),
        (
            "X-Frame-Options",
            "Missing X-Frame-Options (Clickjacking Protection)",
            Severity.LOW,
            "Defends users against UI redressing and Clickjacking attacks by preventing page embedding in unauthorized iframes.",
            "Configure 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors'."
        ),
        (
            "Referrer-Policy",
            "Missing Referrer-Policy Header",
            Severity.INFO,
            "Governs how much referrer information should be included with requests made from your site.",
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
        ),
        (
            "Permissions-Policy",
            "Missing Permissions-Policy Header",
            Severity.INFO,
            "Restricts the use of browser features and APIs (e.g. camera, microphone, geolocation).",
            "Configure a Permissions-Policy header to disable unused browser device APIs."
        )
    ]

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url

        # 1. Missing Security Headers
        for h_name, title, sev, desc, rec in header_specs:
            if h_name in res.missing_security_headers:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-HEADER-{h_name.upper().replace('-', '')}-{idx}",
                    title=title,
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    description=desc,
                    evidence=f"{h_name} header was absent in response from {res.url}.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation=rec,
                    limitations="Deterministic header verification; directive policy effectiveness was not evaluated.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 2. Verbose Server Banners & Technology Disclosure
        verbose_banners = []
        if res.server_header and re.search(r"[\d/]", res.server_header):
            verbose_banners.append(f"Server: {res.server_header}")
        if res.powered_by_header:
            verbose_banners.append(f"X-Powered-By: {res.powered_by_header}")
        if getattr(res, "framework_headers", None):
            for fk, fv in res.framework_headers.items():
                verbose_banners.append(f"{fk}: {fv}")

        if verbose_banners:
            findings.append(OWASPFinding.create(
                id=f"OWASP-A05-BANNER-{idx}",
                title="Verbose Web Server Banner Information Disclosure",
                owasp_category=OwaspCategory.A05_2021.value,
                severity=Severity.LOW,
                confidence=Confidence.OBSERVED,
                description=(
                    "The web server exposes detailed software names and versions in HTTP response headers, "
                    "assisting adversaries in targeted vulnerability mapping."
                ),
                evidence=f"Exposed server banners: {'; '.join(verbose_banners)}",
                affected_asset=res.url,
                endpoint=endpoint_url,
                http_method="GET",
                detection_type=DetectionType.PASSIVE.value,
                recommendation="Mask or suppress verbose banners (e.g., 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx, 'expose_php = Off' in php.ini).",
                limitations="Banner masking reduces information disclosure but does not remediate underlying software flaws.",
                references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
            ))
            idx += 1

        # 3. Directory Listing Detection
        if res.body_sample:
            dir_snippet = check_directory_listing(res.body_sample)
            if dir_snippet:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-DIRLIST-{idx}",
                    title="Directory Listing Enabled",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.PROBABLE,
                    description=(
                        "The web server appears to have directory browsing enabled, visibly exposing file "
                        "structures and directories to unauthenticated users."
                    ),
                    evidence=f"Directory index pattern detected in HTTP response from {res.url}: {dir_snippet}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Disable directory indexing in the web server configuration (e.g., 'Options -Indexes' in Apache, 'autoindex off' in Nginx).",
                    limitations="Passive HTML analysis of landing page; directory trees were not traversed.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 4. Verbose Error Disclosure (Stack Traces)
        if res.body_sample:
            err_info = check_verbose_error_disclosure(res.body_sample, res.status_code)
            if err_info:
                engine_name, err_snippet = err_info
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-ERR-DISCLOSURE-{idx}",
                    title="Verbose Error Message Disclosure",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.PROBABLE,
                    description=(
                        f"The application exposes internal diagnostic error information ({engine_name} stack trace/exception details) "
                        "in HTTP responses, revealing implementation details and internal architecture."
                    ),
                    evidence=f"HTTP response exposes {engine_name} diagnostic error information: {err_snippet}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Disable detailed error messages and debug stack traces in production; implement generic custom error pages.",
                    limitations="Identified from observed response body; internal log pipelines were not inspected.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 5. Debug Mode Indicators
        if res.body_sample:
            dbg_info = check_debug_mode_exposure(res.body_sample)
            if dbg_info:
                fw_name, dbg_snippet = dbg_info
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-DEBUG-MODE-{idx}",
                    title="Potential Debug Mode Exposure",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.PROBABLE,
                    description=(
                        f"The web application appears to be running in active debug/developer mode ({fw_name}), "
                        "potentially exposing interactive debug consoles, internal state, and code execution facilities."
                    ),
                    evidence=f"HTTP response exposes {fw_name} debug page signature: {dbg_snippet}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Ensure debug mode is disabled in production environments (e.g. set DEBUG=False or APP_DEBUG=false).",
                    limitations="Identified via static signature matching; debugger consoles were not actively interacted with.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 6. HTTP Methods Misconfiguration & TRACE
        if getattr(res, "options_methods", None):
            risky_methods, trace_enabled = check_http_methods(res.options_methods)
            if trace_enabled:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-TRACE-ENABLED-{idx}",
                    title="HTTP TRACE Method Enabled",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description="The web server advertises support for the HTTP TRACE method, which can be leveraged in Cross-Site Tracing (XST) attacks.",
                    evidence="Server advertises TRACE in the Allow header.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="OPTIONS",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Disable the HTTP TRACE method in web server configuration (e.g. 'TraceEnable off' in Apache).",
                    limitations="Observed via Allow header; TRACE reflection was not actively exploited.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

            if risky_methods:
                methods_str = ", ".join(risky_methods)
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-UNNECESSARY-METHODS-{idx}",
                    title="Potentially Unnecessary HTTP Method Exposed",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    description="The web server advertises potentially unnecessary or risky HTTP methods that may not be required for standard application operation.",
                    evidence=f"Server advertises potentially unnecessary methods in Allow header: {methods_str}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="OPTIONS",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Review allowed HTTP methods in web server configuration and disable unused methods (e.g., PUT, DELETE).",
                    limitations="Passive inspection of Allow header; methods were not executed or exploited.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 7. HTTPS Certificate Misconfiguration
        if getattr(res, "tls_cert_info", None):
            cert_info = res.tls_cert_info
            if cert_info.get("is_expired"):
                exp_date = cert_info.get("expires_at", "in the past")
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-CERT-EXPIRED-{idx}",
                    title="HTTPS Certificate Expired",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description="The SSL/TLS certificate presented by the HTTPS service has expired, causing browser security warnings and broken trust.",
                    evidence=f"HTTPS certificate expired on {exp_date}.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Renew and install a valid TLS certificate immediately.",
                    limitations="Deterministic certificate expiration verification.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

            if cert_info.get("hostname_mismatch"):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-CERT-MISMATCH-{idx}",
                    title="HTTPS Certificate Hostname Mismatch",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description="The SSL/TLS certificate presented does not match the requested target hostname or IP address.",
                    evidence="Certificate Subject Common Name (CN) or SAN does not match target host.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Ensure the TLS certificate is issued for the correct domain/hostname and Subject Alternative Names (SAN).",
                    limitations="Deterministic certificate identity verification.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 8. HTTP to HTTPS Redirection Posture
        if res.url.startswith("http://") and not (res.final_url and res.final_url.startswith("https://")):
            has_https = any(
                r.url.startswith("https://") or (r.final_url and r.final_url.startswith("https://"))
                for r in context.http_results
            )
            if has_https:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A05-HTTP-NO-REDIRECT-{idx}",
                    title="HTTP Service Does Not Enforce HTTPS Redirection",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    description="The target operates an HTTPS service, but HTTP connections remain accessible without automatic redirection to HTTPS.",
                    evidence=f"HTTP endpoint '{res.url}' responds without redirecting to HTTPS.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Configure the web server to automatically redirect all HTTP traffic to HTTPS (e.g. 301 Permanent Redirect).",
                    limitations="Observed landing page response; application requirements may vary.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

        # 9. Robots.txt Information Disclosure
        if getattr(res, "robots_txt_disallowed", None) and res.robots_txt_disallowed:
            disallowed_str = ", ".join(res.robots_txt_disallowed[:5])
            findings.append(OWASPFinding.create(
                id=f"OWASP-A05-ROBOTS-DISALLOW-{idx}",
                title="Robots.txt Discloses Sensitive Path Disallow Directives",
                owasp_category=OwaspCategory.A05_2021.value,
                severity=Severity.LOW,
                confidence=Confidence.CONFIRMED,
                description="The robots.txt file discloses administrative, private, or internal directory structures via Disallow directives.",
                evidence=f"robots.txt discloses sensitive paths via Disallow directives: {disallowed_str}",
                affected_asset=res.url,
                endpoint=f"{res.url.rstrip('/')}/robots.txt",
                detection_type=DetectionType.PASSIVE.value,
                recommendation="Ensure paths listed in robots.txt are properly protected with strict authentication and authorization.",
                limitations="Evaluates public robots.txt file.",
                references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
            ))
            idx += 1

    # 10. Legacy / Unnecessary Services from ScanResult
    if context.scan_result:
        legacy_findings = check_legacy_services(context.scan_result)
        for lf in legacy_findings:
            findings.append(OWASPFinding.create(
                id=f"OWASP-{lf.id}",
                title=lf.title,
                owasp_category=OwaspCategory.A05_2021.value,
                severity=lf.severity,
                confidence=lf.confidence,
                description=lf.description,
                evidence=lf.evidence,
                affected_asset=lf.affected_asset,
                endpoint=f"{lf.affected_asset}:{lf.affected_port}",
                http_method="TCP",
                detection_type=DetectionType.PASSIVE.value,
                recommendation=lf.recommendation,
                limitations=lf.limitations,
                references=lf.references
            ))

    return findings

def detect_vulnerable_components(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A06:2021 - Vulnerable and Outdated Components.
    Correlates software/version CVEs from Phase 4 vulnerability intelligence across all services.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    # Map existing Phase 4 CVE findings across all discovered services to A06
    for f in context.existing_findings:
        if f.category == "Vulnerability Intelligence":
            findings.append(OWASPFinding.create(
                id=f"OWASP-A06-{f.id}",
                title=f"Outdated Component: {f.product or f.affected_service or 'Software'} ({f.title})",
                owasp_category=OwaspCategory.A06_2021.value,
                severity=f.severity,
                confidence=f.confidence,
                description=f.description,
                evidence=f.evidence,
                affected_asset=f.affected_asset,
                endpoint=f.endpoint or f.affected_asset,
                http_method="GET",
                detection_type=DetectionType.CORRELATED.value,
                recommendation=f.recommendation or "Upgrade affected component to the latest stable and patched release.",
                limitations="Correlated from detected software version; actual exploitability depends on runtime configuration and code path accessibility.",
                references=f.references or ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]
            ))
            idx += 1

    return findings

def detect_identification_authentication_weakness(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A07:2021 - Identification and Authentication Failures.
    Detects credential transmission over unencrypted HTTP and cookies missing HttpOnly flag.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url

        # 1. Login or Password Form Over HTTP
        is_cleartext = res.url.lower().startswith("http://")
        for form in res.forms:
            action_url = form.get("action", "")
            action_cleartext = action_url.lower().startswith("http://")
            has_password = form.get("has_password", False)
            action_is_auth = any(tok in action_url.lower() for tok in ["login", "auth", "signin", "session"])

            if (has_password or action_is_auth) and (is_cleartext or action_cleartext):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A07-CLEARTEXT-AUTH-{idx}",
                    title="Cleartext Authentication Transmission (Login Over HTTP)",
                    owasp_category=OwaspCategory.A07_2021.value,
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        "An authentication or password submission form is hosted or transmitted over unencrypted HTTP, "
                        "exposing user credentials to network interception."
                    ),
                    evidence=f"Authentication form with action '{action_url}' is served over unencrypted HTTP ({res.url}).",
                    affected_asset=res.url,
                    endpoint=action_url or endpoint_url,
                    http_method=form.get("method", "POST"),
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Serve all authentication forms and submission endpoints exclusively over TLS/HTTPS.",
                    limitations="Passive HTML form analysis; no credentials were submitted.",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"]
                ))
                idx += 1

        # 2. Cookies missing HttpOnly
        for c in res.cookies:
            if not c.get("httponly"):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A07-COOKIE-HTTPONLY-{idx}",
                    title=f"Cookie Missing HttpOnly Flag ({c.get('name')})",
                    owasp_category=OwaspCategory.A07_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"The cookie '{c.get('name')}' is set without the HttpOnly attribute, making it accessible "
                        "to client-side scripts and vulnerable to theft via Cross-Site Scripting (XSS)."
                    ),
                    evidence=f"Cookie '{c.get('name')}' missing HttpOnly attribute.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Set the 'HttpOnly' flag on all cookies storing session identifiers or sensitive state.",
                    limitations="Non-session client-side state cookies may legitimately omit the HttpOnly flag.",
                    references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"]
                ))
                idx += 1

    return findings

def detect_software_data_integrity_failures(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A08:2021 - Software and Data Integrity Failures.
    Detects external scripts missing Subresource Integrity (SRI) and Mixed Content inclusions.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url

        for item in res.insecure_resources:
            if "External script missing SRI" in item:
                script_src = item.split(": ", 1)[-1] if ": " in item else item
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A08-SRI-{idx}",
                    title="External Script Inclusion Missing Subresource Integrity (SRI)",
                    owasp_category=OwaspCategory.A08_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    description=(
                        "An externally hosted JavaScript resource is loaded without Subresource Integrity (SRI) "
                        "hashes, leaving the application vulnerable if the external CDN is compromised."
                    ),
                    evidence=f"External script loaded without integrity hash: {script_src}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Add 'integrity' cryptographic hashes and 'crossorigin=\"anonymous\"' attributes to external scripts.",
                    limitations="Evaluates landing page static script tags.",
                    references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"]
                ))
                idx += 1

            elif "Mixed Content" in item:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-A08-MIXED-{idx}",
                    title="Mixed Content: Insecure Subresource Loaded Over HTTP",
                    owasp_category=OwaspCategory.A08_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description="An HTTPS page loads subresources over unencrypted HTTP, allowing man-in-the-middle tampering.",
                    evidence=f"Insecure resource inclusion: {item}",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    http_method="GET",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Migrate all included assets (scripts, stylesheets, media) to HTTPS.",
                    limitations="Evaluates static tags parsed from landing page HTML.",
                    references=["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"]
                ))
                idx += 1

    return findings

def detect_security_logging_monitoring_gaps(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A09:2021 - Security Logging and Monitoring Failures.
    Documents structural assessment boundaries with zero false positives.
    """
    findings: List[OWASPFinding] = []
    web_urls = context.get_web_urls()
    if web_urls:
        findings.append(OWASPFinding.create(
            id="OWASP-A09-LOGGING-NOTE-1",
            title="Security Logging and Monitoring Gap (Assessment Limitation)",
            owasp_category=OwaspCategory.A09_2021.value,
            severity=Severity.INFO,
            confidence=Confidence.INFORMATIONAL,
            description=(
                "OWASP A09:2021 Security Logging and Monitoring Failures cannot be verified from non-intrusive external "
                "network assessment without internal access to log management and SIEM systems."
            ),
            evidence="External network reconnaissance cannot evaluate centralized logging or intrusion detection pipelines.",
            affected_asset=web_urls[0],
            endpoint=web_urls[0],
            detection_type=DetectionType.PASSIVE.value,
            recommendation="Establish centralized audit logging for security events, authentication attempts, and authorization failures.",
            limitations="External black-box reconnaissance cannot inspect internal log management systems.",
            references=["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"]
        ))
    return findings

def detect_ssrf_indicators(context: AssessmentContext) -> List[OWASPFinding]:
    """
    OWASP A10:2021 - Server-Side Request Forgery.
    Heuristically identifies candidate parameters commonly used for remote URL fetching
    without initiating outbound network requests.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url
        observed = [p.lower() for p in res.observed_parameters]
        matched = [p for p in observed if p in SSRF_CANDIDATE_PARAMS]

        if matched:
            param_list_str = ", ".join(sorted(matched))
            findings.append(OWASPFinding.create(
                id=f"OWASP-A10-SSRF-PARAM-{idx}",
                title="Potential SSRF Attack Surface (Candidate Parameter)",
                owasp_category=OwaspCategory.A10_2021.value,
                severity=Severity.LOW,
                confidence=Confidence.POTENTIAL,
                description=(
                    "The endpoint accepts input parameter(s) commonly associated with remote URL fetching or redirection. "
                    "If processed server-side without validation, this could enable Server-Side Request Forgery (SSRF)."
                ),
                evidence=f"Observed SSRF candidate parameter(s) [{param_list_str}] on endpoint {endpoint_url}.",
                affected_asset=res.url,
                endpoint=endpoint_url,
                http_method="GET",
                parameter=param_list_str,
                detection_type=DetectionType.PASSIVE.value,
                recommendation="Enforce strict allowlists for destination domains and disallow private IP ranges (RFC 1918, 127.0.0.0/8, 169.254.169.254).",
                limitations="Parameter name heuristic only. No outbound network requests or payloads were sent. Requires manual validation.",
                references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"]
            ))
            idx += 1

    return findings

def detect_csrf_weaknesses(context: AssessmentContext) -> List[OWASPFinding]:
    """
    CSRF Weakness Analysis.
    Detects state-changing POST forms lacking anti-CSRF token input fields.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url

        for form in res.forms:
            method = form.get("method", "GET").upper()
            action_url = form.get("action", endpoint_url)
            has_csrf = form.get("has_csrf_token", False)

            if method == "POST" and not has_csrf:
                findings.append(OWASPFinding.create(
                    id=f"OWASP-CSRF-FORM-{idx}",
                    title="Potential CSRF Vulnerability (State-Changing Form Missing Anti-CSRF Token)",
                    owasp_category=OwaspCategory.A01_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.POTENTIAL,
                    description=(
                        "A state-changing HTML form (POST) was detected without an embedded anti-CSRF token field, "
                        "which may allow unauthorized cross-site actions on behalf of authenticated users."
                    ),
                    evidence=f"HTML form with method='POST' and action='{action_url}' contains no recognized anti-CSRF token field.",
                    affected_asset=res.url,
                    endpoint=action_url,
                    http_method="POST",
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Implement anti-CSRF tokens (Synchronizer Token Pattern) or SameSite cookie protections on all state-changing endpoints.",
                    limitations="Static HTML analysis. Does not evaluate tokens passed via custom headers (e.g. X-CSRF-Token) or JSON payloads.",
                    references=["https://owasp.org/www-community/attacks/csrf"]
                ))
                idx += 1

    return findings

def detect_cookie_security(context: AssessmentContext) -> List[OWASPFinding]:
    """
    Cookie Security Analysis.
    Evaluates Secure and SameSite attributes on cookies transmitted over HTTPS or HTTP.
    """
    findings: List[OWASPFinding] = []
    idx = 1

    for res in context.http_results:
        if not res.status_code:
            continue

        endpoint_url = res.final_url or res.url
        is_https = res.url.lower().startswith("https://") or endpoint_url.lower().startswith("https://")

        for c in res.cookies:
            c_name = c.get("name", "unknown")

            # 1. Missing Secure flag over HTTPS
            if is_https and not c.get("secure"):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-COOKIE-SECURE-{idx}",
                    title=f"Cookie Missing Secure Flag Over HTTPS ({c_name})",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    description=(
                        f"The cookie '{c_name}' was set over HTTPS without the Secure flag, allowing the browser "
                        "to transmit it over unencrypted HTTP connections."
                    ),
                    evidence=f"Cookie '{c_name}' transmitted over HTTPS without Secure attribute.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Set the 'Secure' attribute on all cookies transmitted over TLS.",
                    limitations="Evaluates cookie headers returned by landing page.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

            # 2. Missing SameSite attribute
            if not c.get("samesite"):
                findings.append(OWASPFinding.create(
                    id=f"OWASP-COOKIE-SAMESITE-{idx}",
                    title=f"Cookie Missing SameSite Protection ({c_name})",
                    owasp_category=OwaspCategory.A05_2021.value,
                    severity=Severity.LOW,
                    confidence=Confidence.OBSERVED,
                    description=(
                        f"The cookie '{c_name}' does not specify a SameSite attribute, making it eligible for cross-site "
                        "requests and potentially exposing the application to CSRF."
                    ),
                    evidence=f"Cookie '{c_name}' has no SameSite attribute configured.",
                    affected_asset=res.url,
                    endpoint=endpoint_url,
                    detection_type=DetectionType.PASSIVE.value,
                    recommendation="Set 'SameSite=Lax' or 'SameSite=Strict' on all cookies.",
                    limitations="Evaluates cookie headers returned by landing page.",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"]
                ))
                idx += 1

    return findings

def run_all_owasp_detectors(context: AssessmentContext) -> List[OWASPFinding]:
    """
    Executes all deterministic OWASP detectors against the assessment context.
    Returns the aggregated list of raw findings.
    """
    all_findings: List[OWASPFinding] = []
    detectors = [
        detect_broken_access_control,
        detect_cryptographic_failures,
        detect_injection_indicators,
        detect_insecure_design,
        detect_security_misconfiguration,
        detect_vulnerable_components,
        detect_identification_authentication_weakness,
        detect_software_data_integrity_failures,
        detect_security_logging_monitoring_gaps,
        detect_ssrf_indicators,
        detect_csrf_weaknesses,
        detect_cookie_security
    ]

    for det in detectors:
        try:
            results = det(context)
            all_findings.extend(results)
        except Exception as e:
            logger.error(f"Error executing detector {det.__name__}: {e}")

    return all_findings
