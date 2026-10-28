"""
AlaviTrace Phase 12 - Deterministic OWASP Top 10 (2021) Coverage Engine.
Provides honest, deterministic accounting of supported vs. architectural review boundaries.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from alavitrace.core.models import Finding
from alavitrace.assessment.models import OwaspCategory

@dataclass
class OWASPCoverageItem:
    code: str
    name: str
    support_level: str  # "Supported" or "Architectural Review"
    findings_count: int = 0
    finding_ids: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "name": self.name,
            "support_level": self.support_level,
            "findings_count": self.findings_count,
            "finding_ids": self.finding_ids,
            "capabilities": self.capabilities,
            "limitations": self.limitations
        }

@dataclass
class OWASPCoverage:
    categories: Dict[str, OWASPCoverageItem] = field(default_factory=dict)
    total_supported: int = 7
    total_architectural_review: int = 3
    total_findings_mapped: int = 0
    summary_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_supported": self.total_supported,
            "total_architectural_review": self.total_architectural_review,
            "total_findings_mapped": self.total_findings_mapped,
            "summary_notes": self.summary_notes,
            "categories": {code: item.to_dict() for code, item in self.categories.items()}
        }

OWASP_TAXONOMY_DEFINITIONS = {
    "A01:2021": {
        "name": "Broken Access Control",
        "support_level": "Supported",
        "capabilities": [
            "Directory listing exposure checks",
            "Sensitive path identification (e.g., .git, .env, backups, admin panels)",
            "Disallowed paths extraction from robots.txt",
            "Path traversal candidate parameter validation",
            "CSRF token absence detection on HTML state-changing forms"
        ],
        "limitations": [
            "Automated black-box testing cannot evaluate multi-tenant data isolation or vertical/horizontal authorization logic without authenticated role contexts."
        ]
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "support_level": "Supported",
        "capabilities": [
            "TLS certificate expiration and issuer inspection",
            "Cleartext HTTP transport detection for sensitive services",
            "Sensitive cookies transmitted over unencrypted HTTP without Secure flag"
        ],
        "limitations": [
            "Internal cryptographic algorithms, secret key management, and cryptographic entropy cannot be evaluated from external network probes."
        ]
    },
    "A03:2021": {
        "name": "Injection",
        "support_level": "Supported",
        "capabilities": [
            "Deterministic SQL error signature detection across multiple database engines",
            "Reflected parameter validation for cross-site scripting (XSS) characters",
            "Command injection character reflection detection"
        ],
        "limitations": [
            "Destructive SQL injection, out-of-band injection, and second-order blind injection are intentionally out of scope to prevent target data loss or downtime."
        ]
    },
    "A04:2021": {
        "name": "Insecure Design",
        "support_level": "Architectural Review",
        "capabilities": [],
        "limitations": [
            "Insecure design represents fundamental architecture and business-logic deficiencies. Requires threat modeling, secure design review, and code-level architectural analysis."
        ]
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "support_level": "Supported",
        "capabilities": [
            "Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)",
            "Server header and technology version disclosure",
            "Framework identification headers (e.g. X-Powered-By)",
            "Potentially dangerous HTTP methods enumeration (OPTIONS, TRACE, PUT, DELETE)"
        ],
        "limitations": [
            "Server OS configuration files, cloud IAM settings, container runtime policies, and internal permissions cannot be audited externally."
        ]
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "support_level": "Supported",
        "capabilities": [
            "Service banner and CPE extraction from Nmap reconnaissance",
            "NVD CVE intelligence correlation and CVSS severity scoring",
            "Deterministic prioritization of high-risk vulnerability candidates"
        ],
        "limitations": [
            "External banner detection may misidentify software if banners are customized or backported; client-side libraries and internal dependencies require SBOM/SCA analysis."
        ]
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "support_level": "Supported",
        "capabilities": [
            "Session cookies lacking HttpOnly, Secure, or SameSite protections",
            "Cleartext Basic authentication headers exposure",
            "Session identifiers exposed in URLs or GET parameters"
        ],
        "limitations": [
            "Credential stuffing, automated brute-force attacks, multi-factor authentication bypass, and session fixation verification are prohibited."
        ]
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "support_level": "Architectural Review",
        "capabilities": [
            "Inspection of external script resources missing Subresource Integrity (SRI) attributes"
        ],
        "limitations": [
            "CI/CD pipeline integrity, auto-update mechanisms, code signing, and untrusted deserialization logic require internal source code and infrastructure auditing."
        ]
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "support_level": "Architectural Review",
        "capabilities": [],
        "limitations": [
            "Internal logging policies, centralized SIEM pipelines, alert thresholds, and incident response tracking are internal system properties invisible to external scanning."
        ]
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "support_level": "Supported",
        "capabilities": [
            "Discovery of URL/URI-accepting parameters (e.g., dest, redirect, url, target, callback)",
            "Detection of open redirection behaviors on HTTP endpoints"
        ],
        "limitations": [
            "Internal intranet requests, cloud metadata service probing, and out-of-band callback triggers are not executed to prevent unintended infrastructure disruption."
        ]
    }
}

def get_owasp_coverage_summary(findings: List[Finding]) -> OWASPCoverage:
    """
    Computes a deterministic OWASP Top 10 (2021) coverage summary from the findings.
    Maps findings to categories honestly, showing empirical capabilities and boundaries.
    """
    categories: Dict[str, OWASPCoverageItem] = {}

    for code, meta in OWASP_TAXONOMY_DEFINITIONS.items():
        categories[code] = OWASPCoverageItem(
            code=code,
            name=meta["name"],
            support_level=meta["support_level"],
            findings_count=0,
            finding_ids=[],
            capabilities=list(meta["capabilities"]),
            limitations=list(meta["limitations"])
        )

    total_mapped = 0
    for finding in findings:
        cat_code = None
        # Check owasp_category attribute
        if finding.owasp_category:
            for code in OWASP_TAXONOMY_DEFINITIONS.keys():
                if code in finding.owasp_category:
                    cat_code = code
                    break

        # Check title / category keywords fallback
        if not cat_code:
            t = (finding.title or "").lower()
            c = (finding.category or "").lower()
            if "injection" in t or "sql" in t or "xss" in t or "command" in t:
                cat_code = "A03:2021"
            elif "access control" in t or "directory listing" in t or "path traversal" in t or "csrf" in t:
                cat_code = "A01:2021"
            elif "security header" in c or "misconfiguration" in t or "missing security header" in t or "server header" in t:
                cat_code = "A05:2021"
            elif "vulnerability intelligence" in c or "cve" in t or finding.cve_ids:
                cat_code = "A06:2021"
            elif "cookie" in t or "authentication" in t or "session" in t:
                cat_code = "A07:2021"
            elif "tls" in t or "certificate" in t or "cleartext" in t:
                cat_code = "A02:2021"
            elif "ssrf" in t or "redirect" in t:
                cat_code = "A10:2021"

        if cat_code and cat_code in categories:
            categories[cat_code].findings_count += 1
            if finding.id not in categories[cat_code].finding_ids:
                categories[cat_code].finding_ids.append(finding.id)
            total_mapped += 1

    notes = [
        "7 of 10 OWASP Top 10 (2021) categories are actively supported via deterministic detection & validation.",
        "3 categories (A04: Insecure Design, A08: Software/Data Integrity, A09: Logging/Monitoring) require architectural review, threat modeling, or source code audit and cannot be reliably evaluated via external black-box scanning."
    ]

    return OWASPCoverage(
        categories=categories,
        total_supported=7,
        total_architectural_review=3,
        total_findings_mapped=total_mapped,
        summary_notes=notes
    )
