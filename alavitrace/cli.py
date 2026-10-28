import argparse
import sys
import os
import logging
from datetime import datetime
from typing import Optional, List

from alavitrace import __version__
from alavitrace.core.validator import validate_target
from alavitrace.core.logging import setup_logging
from alavitrace.scanners.nmap_scanner import (
    NmapScanner,
    NmapError,
    NmapNotFoundError,
    NmapExecutionError,
    NmapTimeoutError
)
from alavitrace.parsers.nmap_parser import NmapParser, NmapParseError
from alavitrace.core.models import (
    ScanResult,
    HttpResult,
    Finding,
    Severity,
    FindingLifecycle,
    Assessment,
    AssessmentSummary,
    determine_technical_category
)
from alavitrace.enumeration.http import build_http_urls, HttpEnumerator
from alavitrace.analysis.recommendations import RecommendationEngine
from alavitrace.intelligence.nvd import NVDProvider
from alavitrace.analysis.vulnerability import VulnerabilityCorrelator
from alavitrace.analysis.prioritization import VulnerabilityPrioritizer, PrioritizationResult
from alavitrace.ai.gemini import GeminiAIProvider
from alavitrace.ai.analyst import SecurityAnalyst
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.reporting.json_report import generate_json_report
from alavitrace.reporting.markdown_report import generate_markdown_report
from alavitrace.reporting.html_report import generate_html_report
from alavitrace.assessment.models import AssessmentContext, AssessmentResult
from alavitrace.assessment.engine import AssessmentEngine
from alavitrace.assessment.coverage import get_owasp_coverage_summary
from alavitrace.validation import ValidationEngine, ValidationEngineResult
from alavitrace.attacksurface import AttackSurfaceMapper, AttackSurface

BANNER = f"""
================================================================
  ALAVITRACE v{__version__}
  AI-Assisted Reconnaissance & Security Intelligence Framework
================================================================
  AUTHORIZATION REMINDER:
  Only scan targets you own or have explicit written authorization
  to assess. Unauthorized scanning may violate laws.
================================================================
"""

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="AlaviTrace - AI-Assisted Reconnaissance & Security Intelligence Framework"
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address, hostname, or domain name (e.g. 192.168.56.106 or target.local)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose debugging output"
    )
    parser.add_argument(
        "-o", "--output-dir",
        default="reports",
        help="Directory to save generated assessment reports (default: reports/)"
    )
    parser.add_argument(
        "--pn",
        action="store_true",
        help="Disable host discovery / assume host is online (-Pn in Nmap)"
    )
    parser.add_argument(
        "--keep-xml",
        action="store_true",
        help="Preserve raw Nmap XML file after parsing"
    )
    parser.add_argument(
        "--no-vuln-check",
        action="store_true",
        help="Skip external vulnerability intelligence correlation"
    )
    parser.add_argument(
        "--vuln-provider",
        default="nvd",
        help="Vulnerability intelligence provider to use (default: nvd)"
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=5,
        help="Maximum number of top prioritized vulnerability findings to display (default: 5)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI-assisted security analysis"
    )
    parser.add_argument(
        "--owasp",
        dest="owasp",
        action="store_true",
        default=True,
        help="Enable OWASP Web Security Assessment Engine (default: enabled when HTTP services are discovered)"
    )
    parser.add_argument(
        "--no-owasp",
        dest="owasp",
        action="store_false",
        help="Disable OWASP Web Security Assessment Engine"
    )
    parser.add_argument(
        "--misconfig",
        dest="misconfig",
        action="store_true",
        default=False,
        help="Enable detailed OWASP A05 Security Misconfiguration assessment (included in --owasp by default)"
    )
    parser.add_argument(
        "--injection",
        dest="injection",
        action="store_true",
        default=False,
        help="Enable controlled active OWASP A03 Injection assessment"
    )
    parser.add_argument(
        "--no-injection",
        dest="injection",
        action="store_false",
        help="Disable controlled active OWASP A03 Injection assessment"
    )
    parser.add_argument(
        "--max-injection-requests",
        type=int,
        default=20,
        help="Maximum number of controlled test requests for A03 injection testing (default: 20)"
    )
    parser.add_argument(
        "--validate",
        dest="validate",
        action="store_true",
        default=False,
        help="Enable controlled non-destructive finding validation framework"
    )
    parser.add_argument(
        "--validation-timeout",
        dest="validation_timeout",
        type=int,
        default=5,
        help="Timeout in seconds for validation network checks (default: 5)"
    )
    parser.add_argument(
        "--max-validation-requests",
        dest="max_validation_requests",
        type=int,
        default=10,
        help="Maximum validation requests per candidate (default: 10)"
    )
    parser.add_argument(
        "--attack-surface",
        dest="attack_surface",
        action="store_true",
        default=False,
        help="Enable deterministic attack surface mapping and web endpoint discovery"
    )
    parser.add_argument(
        "--max-depth",
        dest="max_depth",
        type=int,
        default=1,
        help="Maximum crawl depth for attack surface endpoint discovery (default: 1)"
    )
    parser.add_argument(
        "--max-requests",
        dest="max_requests",
        type=int,
        default=20,
        help="Maximum HTTP requests for attack surface mapper (default: 20)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "html", "all"],
        default="all",
        help="Report formats to generate (default: all)"
    )
    return parser.parse_args(args)

def render_cli_summary(scan_result: ScanResult) -> None:
    """Formats and prints a clean, human-readable summary of scan findings."""
    print("\n================================================================")
    print("                      RECONNAISSANCE SUMMARY                    ")
    print("================================================================")

    if not scan_result.hosts:
        print("\n[*] No active hosts or open ports discovered.")
        print("================================================================\n")
        return

    for host in scan_result.hosts:
        print(f"\nTarget: {host.ipv4 or host.target.normalized}")
        print(f"Status: {host.state.upper()}")
        if host.hostname:
            print(f"Hostname: {host.hostname}")
        if host.os_matches:
            print(f"OS Detection: {', '.join(host.os_matches)}")

        print("\nDiscovered Open Services:")
        print("-" * 64)
        if not host.open_ports:
            print("  No open ports found on this host.")
        else:
            for service in host.open_ports:
                port_proto = f"{service.port}/{service.protocol}"
                print(f"  [{port_proto}] Service: {service.name}")
                if service.product != "Unknown":
                    print(f"         Product: {service.product}")
                if service.version != "Unknown":
                    print(f"         Version: {service.version}")
                if service.extra_info:
                    print(f"         Extra Info: {service.extra_info}")
                if service.cpes:
                    print(f"         CPE: {', '.join(service.cpes)}")
                print()
    print("================================================================\n")

def render_http_summary(http_results: List[HttpResult]) -> None:
    """Prints passive HTTP enumeration findings."""
    if not http_results:
        return

    print("================================================================")
    print("                     PASSIVE HTTP ENUMERATION                   ")
    print("================================================================")

    for res in http_results:
        print(f"\nURL: {res.url}")
        if res.error_message:
            print(f"  [*] Error: {res.error_message}")
            continue

        print(f"  Status Code:   {res.status_code}")
        print(f"  Final URL:     {res.final_url}")
        print(f"  Response Time: {res.response_time_ms} ms")
        if res.server_header:
            print(f"  Server Header: {res.server_header}")
        if res.powered_by_header:
            print(f"  X-Powered-By:  {res.powered_by_header}")
        if res.content_type:
            print(f"  Content-Type:  {res.content_type}")

        print("\n  Security Header Status:")
        for header, val in res.security_headers.items():
            print(f"    [+] {header}: {val}")
        for missing in res.missing_security_headers:
            print(f"    [-] {missing}: Missing")
        print()
    print("================================================================\n")

def render_vulnerability_summary(prioritization_result: PrioritizationResult, status_notes: List[str]) -> None:
    """Prints prioritized vulnerability intelligence correlations."""
    print("================================================================")
    print("             PRIORITIZED VULNERABILITY INTELLIGENCE             ")
    print("================================================================")

    if status_notes:
        print("\nVulnerability Provider Status:")
        for note in status_notes:
            print(f"  [*] {note}")

    vuln_findings = [f for f in prioritization_result.prioritized_findings if f.category == "Vulnerability Intelligence"]

    if not vuln_findings:
        print("\n[*] No matching CVEs identified for the detected software.")
        print("================================================================\n")
        return

    print(f"\nVulnerability Intelligence Metrics:")
    print(f"  - Total Correlated CVEs:      {prioritization_result.total_correlated}")
    print(f"  - Prioritized Candidates:     {prioritization_result.prioritized_count}")

    for finding in vuln_findings:
        sev_tag = f"[{finding.severity.value.upper()}]"
        print(f"\n{sev_tag} {finding.title}")
        print(f"  Service:        {finding.affected_service} ({finding.product} {finding.version})")
        print(f"  Asset:          {finding.affected_asset}:{finding.affected_port}")
        print(f"  Confidence:     {finding.confidence.value}")
        print(f"  Source:         {finding.source}")
        print(f"  Evidence:       {finding.evidence}")
        print(f"  Description:    {finding.description[:180]}..." if len(finding.description) > 180 else f"  Description:    {finding.description}")
        print(f"  Recommendation: {finding.recommendation}")
        if finding.references:
            print(f"  References:     {finding.references[0]}")

    additional = max(0, prioritization_result.total_correlated - prioritization_result.prioritized_count)
    if additional > 0:
        print(f"\n[*] {additional} additional correlated CVEs are preserved in the full JSON report.")

    print("\n================================================================\n")

def render_ai_summary(ai_analysis: AIAnalysisResult) -> None:
    """Prints AI-assisted security analysis."""
    print("================================================================")
    print("                   AI-ASSISTED SECURITY ANALYSIS                ")
    print("================================================================")

    if not ai_analysis.is_available:
        print(f"\n[*] AI Analysis Status: {ai_analysis.error_message}")
        print("================================================================\n")
        return

    print(f"\nExecutive Summary:")
    print(f"  {ai_analysis.executive_summary}\n")

    print(f"Attack Surface Overview:")
    print(f"  {ai_analysis.attack_surface_summary}\n")

    if ai_analysis.key_observations:
        print("Key Observations:")
        for obs in ai_analysis.key_observations:
            print(f"  - {obs}")
        print()

    if ai_analysis.investigation_priorities:
        print("Manual Investigation Priorities:")
        for prio in ai_analysis.investigation_priorities:
            print(f"  1. {prio}")
        print()

    if ai_analysis.remediation_summary:
        print("Remediation Summary:")
        for rem in ai_analysis.remediation_summary:
            print(f"  - {rem}")
        print()

    print("================================================================\n")

def render_assessment_summary(assessment: Assessment) -> None:
    """Prints top-level executive assessment metrics and overall risk rating."""
    s = assessment.summary
    if not s:
        return

    print("================================================================")
    print("                   EXECUTIVE ASSESSMENT SUMMARY                 ")
    print("================================================================")
    print(f"Target:                  {assessment.target.normalized} ({assessment.target.target_type})")
    print(f"Overall Risk Rating:     [{s.overall_risk_rating.upper()}]")
    print(f"Discovered Services:     {s.total_services}")
    print(f"Discovered Web Endpoints:{s.total_endpoints}")
    print(f"Total Correlated Findings:{s.total_findings}")
    print(f"  - Critical:            {s.critical_findings}")
    print(f"  - High:                {s.high_findings}")
    print(f"  - Medium:              {s.medium_findings}")
    print(f"  - Low:                 {s.low_findings}")
    print(f"  - Informational:       {s.info_findings}")
    print(f"Validation Status:       Validated: {s.validated_findings} | Not Validated: {s.unvalidated_findings} | Inconclusive: {s.inconclusive_findings}")
    print(f"Attack Surface Score:    {s.attack_surface_score}")
    print("================================================================\n")

def render_findings_summary(findings: List[Finding]) -> None:
    """Prints deterministic security recommendations."""
    if not findings:
        return

    print("================================================================")
    print("                 DETERMINISTIC RECOMMENDATIONS                  ")
    print("================================================================")

    for finding in findings:
        sev_tag = f"[{finding.severity.value.upper()}]"
        print(f"\n{sev_tag} {finding.title}")
        print(f"  Asset:          {finding.affected_asset}")
        print(f"  Evidence:       {finding.evidence}")
def render_owasp_summary(
    owasp_result: AssessmentResult,
    target_str: str,
    prioritized_findings: Optional[List[Finding]] = None
) -> None:
    """Formats and prints OWASP Security Assessment findings (Phases 6–9)."""
    print("================================================================")
    print("             OWASP SECURITY ASSESSMENT")
    print("================================================================")

    # Gather all OWASP findings from owasp_result and prioritized_findings
    from alavitrace.assessment.engine import generate_finding_fingerprint
    combined_owasp: List[Finding] = list(owasp_result.findings)
    if prioritized_findings:
        for pf in prioritized_findings:
            if getattr(pf, "owasp_category", None):
                fp = generate_finding_fingerprint(pf)
                if not any(generate_finding_fingerprint(cf) == fp for cf in combined_owasp):
                    combined_owasp.append(pf)

    if not owasp_result.is_http_available and not combined_owasp:
        print(f"Target: {target_str}\n")
        print("No HTTP/HTTPS service detected.")
        print("OWASP web assessment skipped.")
        print("================================================================\n")
        return

    print(f"Target: {target_str}")
    if not owasp_result.is_http_available:
        print("No HTTP/HTTPS service detected.")
        print("OWASP web assessment skipped.")
        print("----------------------------------------------------------------")
        print("Non-web infrastructure and component OWASP findings shown below:\n")

    a05_findings = [f for f in combined_owasp if getattr(f, "owasp_category", None) and "A05" in f.owasp_category]
    a06_findings = [f for f in combined_owasp if getattr(f, "owasp_category", None) and "A06" in f.owasp_category]
    other_findings = [f for f in combined_owasp if f not in a05_findings and f not in a06_findings]

    if a05_findings:
        print("[A05] Security Misconfiguration\n")
        for f in a05_findings:
            sev_tag = f"[{f.severity.value.upper()}]"
            print(f"{sev_tag} {f.title}")
            loc = f.endpoint or f.affected_asset
            if f.affected_port and not (f.endpoint and str(f.affected_port) in f.endpoint):
                print(f"  Service:    {f.affected_service or 'TCP'}")
                print(f"  Port:       {f.affected_port}/tcp")
            else:
                print(f"  URL:        {loc}")
            print(f"  Confidence: {f.confidence.value}")
            print(f"  Evidence:   {f.evidence}")
            print()
        print("-" * 64 + "\n")

    if a06_findings:
        print("[A06] Vulnerable and Outdated Components\n")
        for f in a06_findings:
            sev_tag = f"[{f.severity.value.upper()}]"
            print(f"{sev_tag} {f.title}")
            m_cve = re.search(r"CVE-\d{4}-\d+", f.title) or re.search(r"CVE-\d{4}-\d+", f.id)
            if m_cve:
                print(f"  CVE:        {m_cve.group(0)}")
            if f.affected_service:
                print(f"  Service:    {f.affected_service}")
            if f.affected_port:
                print(f"  Port:       {f.affected_port}/tcp")
            print(f"  Confidence: {f.confidence.value}")
            print(f"  Source:     {f.source or 'NVD'}")
            print(f"  Evidence:   {f.evidence}")
            print()
        print("-" * 64 + "\n")

    if other_findings:
        for f in other_findings:
            cat_label = f.owasp_category or "OWASP Web Security"
            code = cat_label.split(":")[0] if ":" in cat_label else "OWASP"
            print(f"[{code}] {cat_label}\n")
            sev_tag = f"[{f.severity.value.upper()}]"
            print(f"{sev_tag} {f.title}")
            print(f"  Asset:      {f.endpoint or f.affected_asset}")
            print(f"  Confidence: {f.confidence.value}")
            print(f"  Evidence:   {f.evidence}")
            print()

    print("================================================================\n")

def render_injection_summary(owasp_findings: List[Finding], target_str: str) -> None:
    """Formats and prints controlled A03 Injection Assessment results."""
    print("================================================================")
    print("                    A03 INJECTION ASSESSMENT                    ")
    print("================================================================")

    inj_findings = [
        f for f in owasp_findings
        if (getattr(f, "owasp_category", None) and "A03" in f.owasp_category)
        or "Injection" in f.title or "XSS" in f.title
    ]

    if not inj_findings:
        print(f"Target: {target_str}\n")
        print("[*] No injection vulnerability indicators identified.")
        print("================================================================\n")
        return

    for finding in inj_findings:
        sev_tag = f"[{finding.severity.value.upper()}]"
        print(f"\n{sev_tag} {finding.title}")
        if getattr(finding, "owasp_category", None):
            print(f"  OWASP:          {finding.owasp_category}")
        print(f"  URL:            {getattr(finding, 'url', finding.affected_asset)}")
        if getattr(finding, "parameter", None):
            print(f"  Parameter:      {finding.parameter}")
        print(f"  Confidence:     {finding.confidence.value}")
        if getattr(finding, "detection_type", None):
            print(f"  Detection:      {finding.detection_type.capitalize()}")
        print(f"  Evidence:       \n    {finding.evidence}")
        if getattr(finding, "limitations", None):
            print(f"\n  Limitation:     \n    {finding.limitations}")
        print(f"\n  Recommendation: \n    {finding.recommendation}")
        print("-" * 64)

    print("\n================================================================\n")

def render_validation_summary(engine_result: ValidationEngineResult) -> None:
    """Formats and prints controlled finding validation results."""
    print("================================================================")
    print("           CONTROLLED FINDING VALIDATION (PHASE 9)              ")
    print("================================================================")
    print(f"Candidates Evaluated: {engine_result.total_candidates}")
    print(
        f"Status Summary: "
        f"VALIDATED: {engine_result.validated_count} | "
        f"NOT_VALIDATED: {engine_result.not_validated_count} | "
        f"INCONCLUSIVE: {engine_result.inconclusive_count} | "
        f"NOT_APPLICABLE: {engine_result.not_applicable_count} | "
        f"ERROR: {engine_result.error_count}"
    )
    if hasattr(engine_result, "requests_sent"):
        print(f"Validation Requests Sent: {engine_result.requests_sent} (Limit Reached: {engine_result.request_limit_reached})\n")
    else:
        print()

    if not engine_result.results:
        print("[*] No candidate findings evaluated.")
        print("================================================================\n")
        return

    for fid, res in engine_result.results.items():
        status_tag = f"[{res.status.value}]"
        print(f"{status_tag:<18} Finding: {fid}")
        print(f"  Method:      {res.validation_method}")
        print(f"  Evidence:    {res.evidence}")
        if getattr(res, "limitations", None):
            print(f"  Limitations: {res.limitations}")
        if res.error_message:
            print(f"  Error:       {res.error_message}")
        print("-" * 64)

    print("================================================================\n")

def render_attack_surface_summary(attack_surface: AttackSurface) -> None:
    """Formats and prints an observable attack surface inventory summary."""
    print("================================================================")
    print("         ATTACK SURFACE & WEB ENDPOINT DISCOVERY (PHASE 10)     ")
    print("================================================================")
    print(f"Target: {attack_surface.target}")
    if attack_surface.base_urls:
        print(f"Base URLs: {', '.join(attack_surface.base_urls)}")
    print(f"Total Discovered Endpoints: {len(attack_surface.endpoints)}")
    print(f"Total Exposed Parameters:   {len(attack_surface.parameters)}")
    print(f"Observed HTTP Methods:      {', '.join(attack_surface.methods)}")
    print(f"Observed Redirects:         {len(attack_surface.redirects)}\n")

    if attack_surface.technologies:
        print("Identified Technologies:")
        for t in attack_surface.technologies:
            ver_str = f" v{t.version}" if t.version else ""
            conf_str = t.confidence.value if hasattr(t.confidence, "value") else str(t.confidence)
            print(f"  - {t.name}{ver_str} [{conf_str}] ({t.source})")
        print()

    if attack_surface.endpoints:
        print("Discovered Endpoints:")
        for ep in attack_surface.endpoints[:15]:
            p_str = f" [Params: {', '.join(ep.parameters)}]" if ep.parameters else ""
            st_str = f" ({ep.status_code})" if ep.status_code else ""
            print(f"  {ep.method:<5} {ep.path}{st_str}{p_str} [Source: {ep.source}]")
        if len(attack_surface.endpoints) > 15:
            print(f"  ...and {len(attack_surface.endpoints) - 15} additional endpoints preserved in full JSON report.")
        print()

    if attack_surface.redirects:
        out_scope = [r for r in attack_surface.redirects if r.is_out_of_scope]
        if out_scope:
            print(f"Out-of-Scope Redirects Detected: {len(out_scope)}")
            for r in out_scope[:5]:
                print(f"  [OUT_OF_SCOPE_REDIRECT] {r.source_url} -> {r.target_url}")
            print()

    print("================================================================\n")

def run_pipeline(
    target_str: str,
    verbose: bool = False,
    skip_discovery: bool = False,
    keep_xml: bool = False,
    skip_vuln_check: bool = False,
    vuln_provider_name: str = "nvd",
    max_findings: int = 5,
    skip_ai: bool = False,
    enable_owasp: bool = True,
    enable_injection: bool = False,
    max_injection_requests: int = 20,
    misconfig: bool = False,
    validate: bool = False,
    validation_timeout: int = 5,
    max_validation_requests: int = 10,
    enable_attack_surface: bool = False,
    max_depth: int = 1,
    max_requests: int = 20,
    output_dir: str = "reports",
    report_format: str = "all"
) -> int:
    """Executes the Phase 4.1 Prioritized AlaviTrace Pipeline."""
    logger = setup_logging(verbose=verbose)

    if max_findings < 1:
        logger.error(f"Invalid --max-findings parameter: {max_findings}. Must be at least 1.")
        return 1

    if enable_injection or misconfig:
        enable_owasp = True

    logger.info(f"Phase 1: Validating target input: '{target_str}'")
    target = validate_target(target_str)

    if not target.is_valid:
        logger.error(f"Target Validation Error: {target.error_message}")
        return 1

    logger.info(f"Target Validated: {target.normalized} ({target.target_type})")

    scanner = NmapScanner()
    xml_path = None
    extra_flags = ["-Pn"] if skip_discovery else None

    try:
        # Phase 2: Nmap Reconnaissance
        logger.info("Phase 2: Executing Nmap reconnaissance scan (-sV)...")
        xml_path, cmd = scanner.run_scan(target, extra_args=extra_flags)

        logger.info("Phase 3: Parsing Nmap XML scan results...")
        scan_result = NmapParser.parse_xml_file(xml_path, target=target)

        render_cli_summary(scan_result)

        # Phase 3: Passive HTTP Enumeration & Header Recommendations
        http_results: List[HttpResult] = []
        rec_findings: List[Finding] = []
        enumerator = HttpEnumerator()

        # Legacy services check from network scan result
        legacy_findings = RecommendationEngine.analyze_scan_result(scan_result)
        rec_findings.extend(legacy_findings)

        for host in scan_result.hosts:
            http_urls = build_http_urls(host)
            for port, url in http_urls:
                logger.info(f"Executing passive HTTP enumeration on port {port} ({url})...")
                res = enumerator.enumerate(url)

                # Check advertised OPTIONS methods and safe paths
                options_methods = enumerator.check_options(url)
                if options_methods:
                    res.options_methods = options_methods

                disallowed_paths, sec_found = enumerator.check_safe_paths(url)
                if disallowed_paths:
                    res.robots_txt_disallowed = disallowed_paths
                if sec_found:
                    res.security_txt_found = True

                http_results.append(res)

                findings = RecommendationEngine.analyze_http_result(res)
                for f in findings:
                    f.advance_lifecycle(FindingLifecycle.ANALYZED)
                rec_findings.extend(findings)

        if http_results:
            render_http_summary(http_results)

        # Phase 10: Attack Surface Mapping & Web Endpoint Discovery
        attack_surface: Optional[AttackSurface] = None
        if enable_attack_surface and http_results:
            logger.info(f"Phase 10: Mapping attack surface for '{target.normalized}' (Max Depth: {max_depth}, Max Requests: {max_requests})...")
            mapper = AttackSurfaceMapper(
                authorized_target=target.normalized,
                max_depth=max_depth,
                max_requests=max_requests
            )
            attack_surface = mapper.map_surface(
                target=target,
                http_results=http_results,
                scan_result=scan_result
            )
            render_attack_surface_summary(attack_surface)

        # Phase 4: Vulnerability Intelligence Correlation
        vuln_findings: List[Finding] = []
        status_notes: List[str] = []
        if not skip_vuln_check:
            logger.info("Phase 4: Querying vulnerability intelligence provider...")
            provider = NVDProvider()
            correlator = VulnerabilityCorrelator(provider=provider)
            vuln_findings, status_notes = correlator.correlate_scan_result(scan_result)
            for f in vuln_findings:
                f.advance_lifecycle(FindingLifecycle.CORRELATED)
        else:
            logger.info("Vulnerability check skipped by user flag (--no-vuln-check).")

        # Phase 6/7/8/9: OWASP Web Security Assessment & Controlled Injection
        owasp_result: Optional[AssessmentResult] = None
        owasp_findings: List[Finding] = []
        if enable_owasp:
            logger.info("Executing OWASP Web Security Assessment Engine...")
            owasp_context = AssessmentContext(
                target=target,
                scan_result=scan_result,
                http_results=http_results,
                existing_findings=rec_findings + vuln_findings,
                options={
                    "max_findings": max_findings,
                    "enable_injection": enable_injection,
                    "max_injection_requests": max_injection_requests,
                    "enable_misconfig": misconfig
                }
            )
            owasp_engine = AssessmentEngine()
            owasp_result = owasp_engine.execute(owasp_context)
            owasp_findings = [f for f in owasp_result.findings]
            for f in owasp_findings:
                f.advance_lifecycle(FindingLifecycle.ANALYZED)

        all_findings = vuln_findings + rec_findings + owasp_findings

        # Phase 4.1: Vulnerability Deduplication & Prioritization
        logger.info(f"Phase 4.1: Prioritizing vulnerability findings (Max Top Findings: {max_findings})...")
        prioritizer = VulnerabilityPrioritizer()
        prioritization_result = prioritizer.prioritize(all_findings, max_findings=max_findings)
        for f in prioritization_result.prioritized_findings:
            f.advance_lifecycle(FindingLifecycle.PRIORITIZED)

        # Phase 9/11: Controlled Finding Validation Framework
        validation_engine_result: Optional[ValidationEngineResult] = None
        if validate:
            logger.info("Phase 9/11: Executing Controlled Finding Validation Framework on prioritized candidates...")
            val_engine = ValidationEngine(
                timeout=validation_timeout,
                max_requests=max_validation_requests,
                attack_surface=attack_surface
            )
            validation_engine_result = val_engine.validate_findings(
                findings=prioritization_result.prioritized_findings,
                context={"attack_surface": attack_surface, "http_results": http_results},
                target_scope=target.normalized
            )
            render_validation_summary(validation_engine_result)

            # Re-score, re-rank findings, and advance lifecycle post-validation
            for f in prioritization_result.prioritized_findings:
                score, _ = prioritizer.calculate_priority_score(f)
                f.priority_score = score
                if getattr(f, "validation_result", None):
                    vr_status = getattr(f.validation_result.status, "value", str(f.validation_result.status))
                    if vr_status == "VALIDATED":
                        f.advance_lifecycle(FindingLifecycle.VALIDATED)
                    elif vr_status == "NOT_VALIDATED":
                        f.advance_lifecycle(FindingLifecycle.NOT_VALIDATED)
                    else:
                        f.advance_lifecycle(FindingLifecycle.INCONCLUSIVE)

            prioritization_result.prioritized_findings.sort(key=lambda f: f.priority_score, reverse=True)

        # Ensure all findings have a technical category assigned
        for f in all_findings:
            if not f.technical_category:
                f.technical_category = determine_technical_category(f)

        # Phase 12: Build top-level Assessment and AssessmentSummary
        all_retained = prioritization_result.all_findings
        crit_count = sum(1 for f in all_retained if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in all_retained if f.severity == Severity.HIGH)
        med_count = sum(1 for f in all_retained if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in all_retained if f.severity == Severity.LOW)
        info_count = sum(1 for f in all_retained if f.severity == Severity.INFO)

        val_fs = [f for f in all_retained if getattr(f, "validation_result", None)]
        val_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "VALIDATED")
        not_val_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "NOT_VALIDATED")
        inconc_cnt = sum(1 for f in val_fs if getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "INCONCLUSIVE")

        all_open_services = [s for h in scan_result.hosts for s in h.open_ports]
        tot_services = len(all_open_services)
        tot_endpoints = len(getattr(attack_surface, "endpoints", [])) if attack_surface else 0
        tot_forms = len(getattr(attack_surface, "forms", [])) if attack_surface else 0

        if crit_count > 0:
            overall_rating = "Critical"
        elif high_count > 0:
            overall_rating = "High"
        elif med_count > 0:
            overall_rating = "Medium"
        elif low_count > 0:
            overall_rating = "Low"
        else:
            overall_rating = "Informational"

        assessment_summary = AssessmentSummary(
            total_findings=len(all_retained),
            critical_findings=crit_count,
            high_findings=high_count,
            medium_findings=med_count,
            low_findings=low_count,
            info_findings=info_count,
            validated_findings=val_cnt,
            unvalidated_findings=not_val_cnt,
            inconclusive_findings=inconc_cnt,
            total_services=tot_services,
            total_endpoints=tot_endpoints,
            total_forms=tot_forms,
            attack_surface_score=round(tot_services * 5.0 + tot_endpoints * 2.0 + tot_forms * 3.0, 1),
            overall_risk_rating=overall_rating
        )

        owasp_coverage_obj = get_owasp_coverage_summary(all_retained)
        val_results_list = [f.validation_result for f in prioritization_result.prioritized_findings if getattr(f, "validation_result", None)]

        assessment = Assessment(
            target=target,
            scan_metadata={
                "framework": "AlaviTrace",
                "version": __version__,
                "timestamp": datetime.now().isoformat(),
                "mode": "authorized_assessment"
            },
            hosts=scan_result.hosts,
            services=all_open_services,
            http_results=http_results,
            attack_surface=attack_surface,
            findings=all_retained,
            prioritized_findings=prioritization_result.prioritized_findings,
            validation_results=val_results_list,
            owasp_coverage=owasp_coverage_obj,
            ai_analysis=None,
            summary=assessment_summary
        )

        render_assessment_summary(assessment)

        if enable_owasp and owasp_result is not None:
            render_owasp_summary(owasp_result, target.normalized, prioritized_findings=prioritization_result.prioritized_findings)
            if enable_injection and owasp_result.is_http_available:
                render_injection_summary(owasp_result.findings, target.normalized)

        if not skip_vuln_check:
            render_vulnerability_summary(prioritization_result, status_notes)

        if rec_findings:
            render_findings_summary(rec_findings)

        # Phase 5: AI-Assisted Security Analysis
        ai_analysis: Optional[AIAnalysisResult] = None
        if not skip_ai:
            logger.info("Phase 5: Performing AI-assisted security analysis over prioritized findings...")
            ai_provider = GeminiAIProvider()
            analyst = SecurityAnalyst(provider=ai_provider)
            ai_analysis = analyst.analyze(scan_result, http_results, prioritization_result, owasp_result=owasp_result, attack_surface=attack_surface)
            assessment.ai_analysis = ai_analysis
            render_ai_summary(ai_analysis)
        else:
            logger.info("AI analysis skipped by user flag (--no-ai).")

        # Mark prioritized findings as reported
        for f in prioritization_result.prioritized_findings:
            if f.lifecycle_stage in [FindingLifecycle.DISCOVERED, FindingLifecycle.ANALYZED, FindingLifecycle.CORRELATED, FindingLifecycle.PRIORITIZED]:
                f.advance_lifecycle(FindingLifecycle.REPORTED)

        # Multi-Format Report Generation
        logger.info(f"Generating assessment reports in '{output_dir}/' (Format: {report_format})...")
        generated_files: List[str] = []

        if report_format in ["json", "all"]:
            json_file = generate_json_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir, owasp_result=owasp_result, attack_surface=attack_surface, assessment=assessment)
            generated_files.append(json_file)

        if report_format in ["markdown", "all"]:
            md_file = generate_markdown_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir, owasp_result=owasp_result, attack_surface=attack_surface, assessment=assessment)
            generated_files.append(md_file)

        if report_format in ["html", "all"]:
            html_file = generate_html_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir, owasp_result=owasp_result, attack_surface=attack_surface, assessment=assessment)
            generated_files.append(html_file)

        print("================================================================")
        print("                     REPORTS GENERATED                         ")
        print("================================================================")
        for gf in generated_files:
            print(f"  [+] Saved Report: {gf}")
        print("================================================================\n")

        return 0

    except NmapNotFoundError as e:
        logger.error(f"Nmap Scanner Error: {e}")
        return 1
    except NmapExecutionError as e:
        logger.error(f"Nmap Execution Failure: {e}")
        return 1
    except NmapTimeoutError as e:
        logger.error(f"Nmap Timeout: {e}")
        return 1
    except NmapParseError as e:
        logger.error(f"XML Parsing Error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected Pipeline Error: {e}")
        if verbose:
            logger.exception("Detailed stack trace:")
        return 1
    finally:
        if xml_path and not keep_xml:
            scanner.cleanup_xml(xml_path)

def main():
    print(BANNER)
    args = parse_args()
    sys.exit(run_pipeline(
        args.target,
        verbose=args.verbose,
        skip_discovery=args.pn,
        keep_xml=args.keep_xml,
        skip_vuln_check=args.no_vuln_check,
        vuln_provider_name=args.vuln_provider,
        max_findings=args.max_findings,
        skip_ai=args.no_ai,
        enable_owasp=args.owasp,
        enable_injection=args.injection,
        max_injection_requests=args.max_injection_requests,
        misconfig=args.misconfig,
        validate=args.validate,
        validation_timeout=args.validation_timeout,
        max_validation_requests=args.max_validation_requests,
        enable_attack_surface=args.attack_surface,
        max_depth=args.max_depth,
        max_requests=args.max_requests,
        output_dir=args.output_dir,
        report_format=args.format
    ))

if __name__ == "__main__":
    main()
