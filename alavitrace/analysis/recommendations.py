import logging
import uuid
from typing import List
from alavitrace.core.models import (
    HttpResult,
    Finding,
    ActionRecommendation,
    Severity,
    Confidence,
    ActionImpact
)

logger = logging.getLogger("AlaviTrace")

class RecommendationEngine:
    """
    Evaluates observed technical data (e.g. HttpResult) against deterministic,
    reproducible security hardening rules.
    """

    @staticmethod
    def analyze_http_result(http_result: HttpResult) -> List[Finding]:
        """
        Applies deterministic security rules to an HttpResult instance.

        Returns:
            List of structured Finding objects.
        """
        findings: List[Finding] = []

        if http_result.error_message:
            return findings

        target_asset = http_result.url
        is_https = http_result.url.startswith("https://") or (
            http_result.final_url and http_result.final_url.startswith("https://")
        )

        # 1. Evaluate missing security headers
        for missing_header in http_result.missing_security_headers:
            if missing_header == "X-Content-Type-Options":
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-NOSNIFF-{uuid.uuid4().hex[:6]}",
                    title="Missing X-Content-Type-Options Header",
                    category="Web Security Configuration",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description="The web server does not send the X-Content-Type-Options response header.",
                    evidence=f"Header 'X-Content-Type-Options' was missing from response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Configure the web server to send 'X-Content-Type-Options: nosniff'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    source="AlaviTrace Security Header Rules"
                ))

            elif missing_header == "Content-Security-Policy":
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-CSP-{uuid.uuid4().hex[:6]}",
                    title="Missing Content-Security-Policy (CSP) Header",
                    category="Web Security Configuration",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description="The web application does not enforce a Content-Security-Policy header.",
                    evidence=f"Header 'Content-Security-Policy' was missing from response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Implement a Content-Security-Policy appropriate for the application.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                    source="AlaviTrace Security Header Rules"
                ))

            elif missing_header == "X-Frame-Options":
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-XFO-{uuid.uuid4().hex[:6]}",
                    title="Missing X-Frame-Options Header",
                    category="Web Security Configuration",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description="The web server does not send the X-Frame-Options response header.",
                    evidence=f"Header 'X-Frame-Options' was missing from response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Configure 'X-Frame-Options: SAMEORIGIN' or 'DENY' to protect against clickjacking.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                    source="AlaviTrace Security Header Rules"
                ))

            elif missing_header == "Referrer-Policy":
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-REF-{uuid.uuid4().hex[:6]}",
                    title="Missing Referrer-Policy Header",
                    category="Web Security Configuration",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    description="The web server does not specify a Referrer-Policy header.",
                    evidence=f"Header 'Referrer-Policy' was missing from response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Consider setting a Referrer-Policy such as 'strict-origin-when-cross-origin'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
                    source="AlaviTrace Security Header Rules"
                ))

            elif missing_header == "Permissions-Policy":
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-PERM-{uuid.uuid4().hex[:6]}",
                    title="Missing Permissions-Policy Header",
                    category="Web Security Configuration",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    description="The web server does not specify a Permissions-Policy header.",
                    evidence=f"Header 'Permissions-Policy' was missing from response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Consider setting a Permissions-Policy to restrict browser feature usage.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
                    source="AlaviTrace Security Header Rules"
                ))

            elif missing_header == "Strict-Transport-Security" and is_https:
                findings.append(Finding(
                    id=f"FIND-SEC-HEADER-HSTS-{uuid.uuid4().hex[:6]}",
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    category="Web Security Configuration",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    description="The HTTPS web server does not enforce HTTP Strict Transport Security.",
                    evidence=f"Header 'Strict-Transport-Security' was missing from HTTPS response at {http_result.url}.",
                    affected_asset=target_asset,
                    recommendation="Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on HTTPS servers.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                    source="AlaviTrace Security Header Rules"
                ))

        # 2. Evaluate Server Version Disclosure
        if http_result.server_header:
            findings.append(Finding(
                id=f"FIND-INFO-DISCLOSURE-SERVER-{uuid.uuid4().hex[:6]}",
                title="Detailed Server Version Disclosure",
                category="Information Disclosure",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                description="The web server exposes software version details in the Server response header.",
                evidence=f"Server header value: '{http_result.server_header}'",
                affected_asset=target_asset,
                recommendation="Consider minimizing detailed software version disclosure in HTTP Server response headers.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                source="AlaviTrace Information Disclosure Rules"
            ))

        # 3. Evaluate HTTP to HTTPS Redirection
        if http_result.redirect_chain and len(http_result.redirect_chain) > 1:
            first_url = http_result.redirect_chain[0]
            final_url = http_result.redirect_chain[-1]
            if first_url.startswith("http://") and final_url.startswith("https://"):
                findings.append(Finding(
                    id=f"FIND-INFO-HTTP-REDIRECT-{uuid.uuid4().hex[:6]}",
                    title="HTTP to HTTPS Redirection Enabled",
                    category="Web Security Configuration",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    description="The web server automatically redirects HTTP requests to HTTPS.",
                    evidence=f"Request to '{first_url}' redirected to '{final_url}'.",
                    affected_asset=target_asset,
                    recommendation="Maintain secure TLS enforcement across all web endpoints.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                    source="AlaviTrace Configuration Rules"
                ))

        logger.info(f"Generated {len(findings)} deterministic recommendations for {http_result.url}")
        return findings
