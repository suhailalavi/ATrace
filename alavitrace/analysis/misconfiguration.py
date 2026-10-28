import re
import logging
from typing import List, Dict, Optional, Tuple, Any

from alavitrace.core.models import (
    Severity,
    Confidence,
    Finding,
    HttpResult,
    ScanResult
)
from alavitrace.assessment.models import (
    OwaspCategory,
    DetectionType,
    AssessmentContext,
    OWASPFinding
)

logger = logging.getLogger("AlaviTrace")

# ============================================================================
# Deterministic Signatures for A05: Security Misconfiguration
# ============================================================================

DIRECTORY_LISTING_PATTERNS = [
    re.compile(r"<title>\s*Index of /", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of /", re.IGNORECASE),
    re.compile(r"Directory listing for /", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
    re.compile(r"<a href=\"\?C=N;O=D\">Name</a>", re.IGNORECASE),
    re.compile(r"<a href=\"\?C=M;O=A\">Last modified</a>", re.IGNORECASE),
    re.compile(r"Parent Directory</a>", re.IGNORECASE),
    re.compile(r"<title>Directory Listing:", re.IGNORECASE),
]

ERROR_DISCLOSURE_PATTERNS: Dict[str, List[re.Pattern]] = {
    "Python": [
        re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
        re.compile(r"File \".*?\.py\", line \d+, in ", re.IGNORECASE),
    ],
    "Java": [
        re.compile(r"Exception in thread \"[^\"]+\"", re.IGNORECASE),
        re.compile(r"\tat [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+\.java:\d+\)", re.IGNORECASE),
        re.compile(r"org\.apache\.catalina\.", re.IGNORECASE),
        re.compile(r"org\.springframework\.", re.IGNORECASE),
    ],
    "PHP": [
        re.compile(r"Fatal error:.*?in /.*?\.php on line \d+", re.IGNORECASE),
        re.compile(r"Warning:.*?in /.*?\.php on line \d+", re.IGNORECASE),
        re.compile(r"Parse error:.*?in /.*?\.php on line \d+", re.IGNORECASE),
    ],
    "ASP.NET": [
        re.compile(r"Server Error in '/' Application", re.IGNORECASE),
        re.compile(r"System\.Web\.HttpException", re.IGNORECASE),
        re.compile(r"\[HttpException \(0x80004005\):", re.IGNORECASE),
        re.compile(r"Description: An unhandled exception occurred during the execution", re.IGNORECASE),
    ],
    "Spring": [
        re.compile(r"Whitelabel Error Page", re.IGNORECASE),
        re.compile(r"There was an unexpected error \(type=Internal Server Error", re.IGNORECASE),
    ]
}

DEBUG_MODE_PATTERNS: Dict[str, List[re.Pattern]] = {
    "Werkzeug": [
        re.compile(r"Werkzeug powered traceback interpreter", re.IGNORECASE),
        re.compile(r"<div class=\"debugger\">", re.IGNORECASE),
        re.compile(r"console__icon", re.IGNORECASE),
        re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    ],
    "Django": [
        re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>", re.IGNORECASE),
        re.compile(r"Django Version:.*?Python Executable:", re.IGNORECASE),
    ],
    "Laravel": [
        re.compile(r"<title>.*Ignition</title>", re.IGNORECASE),
        re.compile(r"Whoops! There was an error\.", re.IGNORECASE),
        re.compile(r"flare-app", re.IGNORECASE),
    ],
    "Spring Boot Actuator": [
        re.compile(r"\"_links\":\{\"self\":\{\"href\":\".*?/actuator\"", re.IGNORECASE),
        re.compile(r"\"status\":500,\"error\":\"Internal Server Error\",\"trace\":", re.IGNORECASE),
    ]
}

POTENTIALLY_RISKY_METHODS = {"PUT", "DELETE", "CONNECT"}

LEGACY_SERVICES_MAP: Dict[int, Tuple[str, Severity, str]] = {
    21: ("FTP", Severity.LOW, "Unencrypted File Transfer Protocol service."),
    23: ("Telnet", Severity.MEDIUM, "Unencrypted remote terminal service exposing plaintext credentials."),
    79: ("Finger", Severity.LOW, "Legacy finger user information disclosure protocol."),
    512: ("Rexec", Severity.MEDIUM, "Legacy unencrypted remote execution daemon."),
    513: ("Rlogin", Severity.MEDIUM, "Legacy unencrypted remote login protocol."),
    514: ("Rsh", Severity.MEDIUM, "Legacy unencrypted remote shell protocol.")
}

SENSITIVE_ROBOTS_DIRECTIVES = [
    "/admin", "/administrator", "/config", "/backup", "/backups",
    "/private", "/secret", "/db", "/database", "/manage", "/internal",
    "/api-docs", "/actuator", "/dashboard", "/.git", "/.env"
]


# ============================================================================
# Heuristic & Deterministic Detection Helpers
# ============================================================================

def check_directory_listing(body: str) -> Optional[str]:
    """
    Detects obvious web server directory indexing structures in response bodies.
    Returns matched snippet if found, None otherwise.
    """
    if not body:
        return None
    for pattern in DIRECTORY_LISTING_PATTERNS:
        match = pattern.search(body)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(body), match.end() + 40)
            return body[start:end].strip().replace("\n", " ")
    return None

def check_verbose_error_disclosure(body: str, status_code: Optional[int] = None) -> Optional[Tuple[str, str]]:
    """
    Detects recognizable diagnostic error messages (stack traces, framework exceptions).
    Does NOT flag generic 500 error pages without internal diagnostic information.
    Returns tuple of (engine_name, matched_snippet) or None.
    """
    if not body:
        return None

    # Exclude trivial generic messages
    body_stripped = body.strip().lower()
    if body_stripped in ["internal server error", "500 internal server error", '{"error": "internal server error"}']:
        return None

    for engine, patterns in ERROR_DISCLOSURE_PATTERNS.items():
        for pat in patterns:
            match = pat.search(body)
            if match:
                start = max(0, match.start() - 15)
                end = min(len(body), match.end() + 60)
                snippet = body[start:end].strip().replace("\n", " ")
                return engine, snippet

    return None

def check_debug_mode_exposure(body: str) -> Optional[Tuple[str, str]]:
    """
    Detects framework debug-mode pages (Werkzeug, Django DEBUG, Laravel Ignition).
    Returns tuple of (framework_name, matched_snippet) or None.
    """
    if not body:
        return None

    for framework, patterns in DEBUG_MODE_PATTERNS.items():
        for pat in patterns:
            match = pat.search(body)
            if match:
                start = max(0, match.start() - 15)
                end = min(len(body), match.end() + 60)
                snippet = body[start:end].strip().replace("\n", " ")
                return framework, snippet

    return None

def check_http_methods(methods: List[str]) -> Tuple[List[str], bool]:
    """
    Analyzes advertised HTTP methods from an Allow header or OPTIONS response.
    Returns tuple of (risky_methods_found, trace_enabled).
    """
    methods_upper = [m.strip().upper() for m in methods if m.strip()]
    trace_enabled = "TRACE" in methods_upper
    risky_found = sorted(list(set(methods_upper).intersection(POTENTIALLY_RISKY_METHODS)))
    return risky_found, trace_enabled

def check_robots_txt(body: str) -> List[str]:
    """
    Parses robots.txt content for sensitive Disallow directives.
    Returns list of sensitive paths found.
    """
    if not body or "disallow:" not in body.lower():
        return []

    sensitive_found: List[str] = []
    for line in body.splitlines():
        line_clean = line.strip()
        if line_clean.lower().startswith("disallow:"):
            parts = line_clean.split(":", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                path_lower = path.lower()
                for sensitive in SENSITIVE_ROBOTS_DIRECTIVES:
                    if sensitive in path_lower and path not in sensitive_found:
                        sensitive_found.append(path)
                        break

    return sensitive_found

def check_legacy_services(scan_result: ScanResult) -> List[Finding]:
    """
    Inspects Nmap scan results for unnecessary or legacy unencrypted services (FTP, Telnet, Finger, R-commands).
    Returns list of Finding objects mapped to OWASP A05:2021 - Security Misconfiguration.
    """
    findings: List[Finding] = []
    idx = 1

    for host in scan_result.hosts:
        target_asset = host.ipv4 or host.target.normalized

        for s in host.open_ports:
            if s.port in LEGACY_SERVICES_MAP:
                svc_name, default_sev, desc = LEGACY_SERVICES_MAP[s.port]
                findings.append(Finding(
                    id=f"FIND-A05-LEGACY-{svc_name.upper()}-{idx}",
                    title=f"Potentially Exposed Legacy Service ({svc_name})",
                    category="Security Misconfiguration",
                    severity=default_sev,
                    confidence=Confidence.OBSERVED,
                    description=(
                        f"The host exposes a legacy or unencrypted {svc_name} service on port {s.port}/{s.protocol}. "
                        f"{desc}"
                    ),
                    evidence=f"Legacy service '{s.name}' ({svc_name}) is reachable on TCP/{s.port}.",
                    affected_asset=target_asset,
                    affected_port=s.port,
                    affected_service=s.name,
                    product=s.product,
                    version=s.version,
                    recommendation=(
                        f"Confirm whether {svc_name} is required on port {s.port}. "
                        "Disable unnecessary services and replace unencrypted protocols with secure alternatives (e.g. SSH, SFTP, TLS)."
                    ),
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
                    source="AlaviTrace Security Misconfiguration Engine",
                    owasp_category=OwaspCategory.A05_2021.value,
                    detection_type=DetectionType.PASSIVE.value,
                    limitations="Identified based on open port and service banner. Exploitability depends on network segmentation and authorization."
                ))
                idx += 1

    return findings
