import re
import logging
from typing import List, Dict, Set, Optional

from alavitrace.core.models import Finding
from alavitrace.assessment.models import (
    AssessmentContext,
    AssessmentResult,
    OWASPFinding,
    get_supported_categories
)
from alavitrace.assessment.registry import CheckRegistry, get_default_registry

logger = logging.getLogger("AlaviTrace")

def generate_finding_fingerprint(finding: Finding) -> str:
    """
    Computes a normalized, deterministic identity fingerprint for a security finding
    to enable deduplication between reconnaissance recommendations and OWASP findings.

    Fingerprint components:
      1. Normalized title / finding type
      2. Normalized endpoint / asset URL
      3. Parameter (if applicable)
      4. HTTP method (if applicable)
    """
    # Normalize title by removing non-alphanumeric characters
    norm_title = re.sub(r"[^a-z0-9]", "", finding.title.lower())

    # Map known variations of common findings (e.g., CSP header)
    if "contentsecuritypolicy" in norm_title or "csp" in norm_title:
        norm_title = "missingcontentsecuritypolicy"
    elif "xcontenttypeoptions" in norm_title or "nosniff" in norm_title:
        norm_title = "missingxcontenttypeoptions"
    elif "xframeoptions" in norm_title or "clickjacking" in norm_title:
        norm_title = "missingxframeoptions"
    elif "stricttransportsecurity" in norm_title or "hsts" in norm_title:
        norm_title = "missingstricttransportsecurity"
    elif "referrerpolicy" in norm_title:
        norm_title = "missingreferrerpolicy"
    elif "permissionspolicy" in norm_title:
        norm_title = "missingpermissionspolicy"
    elif "serverversion" in norm_title or "serverbanner" in norm_title:
        norm_title = "serverversiondisclosure"
    elif "directorylisting" in norm_title:
        norm_title = "directorylisting"
    elif "legacyservice" in norm_title or "exposedlegacyservice" in norm_title:
        for proto in ["ftp", "telnet", "finger", "rexec", "rlogin", "rsh"]:
            if proto in norm_title:
                norm_title = f"legacyservice_{proto}"
                break
    elif "cookie" in norm_title:
        flag = "unknown"
        for fl in ["secure", "httponly", "samesite"]:
            if fl in norm_title:
                flag = fl
                break
        norm_title = f"cookie_{flag}_{finding.parameter or ''}"
    elif "cve" in norm_title:
        m = re.search(r"cve\d{4}\d+", norm_title)
        if m:
            norm_title = m.group(0)

    # Normalize asset / endpoint (strip trailing slash and case)
    raw_target = finding.endpoint or finding.affected_asset or ""
    norm_target = raw_target.rstrip("/").lower()

    # Determine port from finding or target URL scheme/port
    port_val = finding.affected_port
    if port_val is None and norm_target:
        try:
            import urllib.parse
            parsed_t = urllib.parse.urlparse(norm_target)
            if parsed_t.port:
                port_val = parsed_t.port
            elif parsed_t.scheme == "http":
                port_val = 80
            elif parsed_t.scheme == "https":
                port_val = 443
        except Exception:
            pass

    norm_port = str(port_val or "")
    norm_param = (finding.parameter or "").lower()
    norm_method = (finding.http_method or "GET").upper()

    return f"{norm_title}|{norm_target}|{norm_port}|{norm_param}|{norm_method}"

def deduplicate_findings(
    new_findings: List[OWASPFinding],
    existing_findings: List[Finding]
) -> List[OWASPFinding]:
    """
    Deduplicates newly generated OWASP findings against existing reconnaissance
    findings and within the OWASP finding set itself.

    If an OWASP finding matches an existing Phase 3 finding (e.g., missing CSP),
    the existing finding is enriched with OWASP metadata to avoid duplicate report entries.
    """
    existing_map: Dict[str, Finding] = {
        generate_finding_fingerprint(f): f for f in existing_findings
    }

    seen_fingerprints: Set[str] = set()
    deduped: List[OWASPFinding] = []

    for f in new_findings:
        fp = generate_finding_fingerprint(f)

        # 1. Check if an equivalent finding already exists from earlier assessment phases
        if fp in existing_map:
            existing = existing_map[fp]
            # Enrich existing finding with OWASP metadata without duplicating
            if not existing.owasp_category and f.owasp_category:
                existing.owasp_category = f.owasp_category
            if not existing.endpoint and f.endpoint:
                existing.endpoint = f.endpoint
            if not existing.detection_type and f.detection_type:
                existing.detection_type = f.detection_type
            logger.debug(f"Merged duplicate finding into existing record: {f.title} ({fp})")
            continue

        # 2. Check for duplicates within the current OWASP check run
        if fp in seen_fingerprints:
            logger.debug(f"Suppressed internal duplicate OWASP finding: {f.title} ({fp})")
            continue

        seen_fingerprints.add(fp)
        deduped.append(f)

    return deduped

class AssessmentEngine:
    """
    Coordinates OWASP Web Security Assessment checks and aggregates findings.
    Enforces HTTP service availability boundaries and deduplication.
    """

    def __init__(self, registry: Optional[CheckRegistry] = None):
        self.registry = registry or get_default_registry()

    def execute(self, context: AssessmentContext) -> AssessmentResult:
        """
        Executes registered OWASP checks against the provided AssessmentContext.

        If no HTTP/HTTPS service is detected on the target, the engine cleanly skips
        assessment without generating artificial findings.
        """
        supported_cat_names = [cat.value for cat in get_supported_categories()]

        # 1. HTTP Service Availability Verification
        if not context.has_http_service():
            logger.info("No HTTP/HTTPS service detected on target. Skipping OWASP web assessment.")
            return AssessmentResult(
                is_http_available=False,
                findings=[],
                executed_checks=[],
                supported_categories=supported_cat_names,
                message="No HTTP/HTTPS service detected. OWASP web assessment skipped.",
                notes=["Reconnaissance identified no active web ports (e.g., 80, 443) or reachable HTTP services."]
            )

        logger.info(f"Executing OWASP web security assessment ({len(self.registry)} registered checks)...")

        raw_findings: List[OWASPFinding] = []
        executed_checks: List[str] = []
        notes: List[str] = []

        # 2. Execute registered checks
        for check in self.registry.get_all():
            try:
                logger.debug(f"Running OWASP check: {check.name}")
                check_findings = check.check(context)
                raw_findings.extend(check_findings)
                executed_checks.append(check.name)
            except Exception as e:
                logger.error(f"Error executing check '{check.name}': {e}")
                notes.append(f"Check '{check.name}' encountered an error: {e}")

        # 3. Deduplicate findings
        deduped_findings = deduplicate_findings(raw_findings, context.existing_findings)

        msg = (
            f"OWASP web assessment completed. Executed {len(executed_checks)} checks, "
            f"identified {len(deduped_findings)} findings."
        )
        logger.info(msg)

        return AssessmentResult(
            is_http_available=True,
            findings=deduped_findings,
            executed_checks=executed_checks,
            supported_categories=supported_cat_names,
            message=msg,
            notes=notes
        )
