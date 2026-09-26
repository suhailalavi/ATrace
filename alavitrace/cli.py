import argparse
import sys
import os
import logging
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
from alavitrace.core.models import ScanResult, HttpResult, Finding
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
        print(f"  Recommendation: {finding.recommendation}")

    print("\n================================================================\n")

def run_pipeline(
    target_str: str,
    verbose: bool = False,
    skip_discovery: bool = False,
    keep_xml: bool = False,
    skip_vuln_check: bool = False,
    vuln_provider_name: str = "nvd",
    max_findings: int = 5,
    skip_ai: bool = False,
    output_dir: str = "reports",
    report_format: str = "all"
) -> int:
    """Executes the Phase 4.1 Prioritized AlaviTrace Pipeline."""
    logger = setup_logging(verbose=verbose)

    if max_findings < 1:
        logger.error(f"Invalid --max-findings parameter: {max_findings}. Must be at least 1.")
        return 1

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

        for host in scan_result.hosts:
            http_urls = build_http_urls(host)
            for port, url in http_urls:
                logger.info(f"Executing passive HTTP enumeration on port {port} ({url})...")
                res = enumerator.enumerate(url)
                http_results.append(res)

                findings = RecommendationEngine.analyze_http_result(res)
                rec_findings.extend(findings)

        if http_results:
            render_http_summary(http_results)

        # Phase 4: Vulnerability Intelligence Correlation
        vuln_findings: List[Finding] = []
        status_notes: List[str] = []
        if not skip_vuln_check:
            logger.info("Phase 4: Querying vulnerability intelligence provider...")
            provider = NVDProvider()
            correlator = VulnerabilityCorrelator(provider=provider)
            vuln_findings, status_notes = correlator.correlate_scan_result(scan_result)
        else:
            logger.info("Vulnerability check skipped by user flag (--no-vuln-check).")

        all_findings = vuln_findings + rec_findings

        # Phase 4.1: Vulnerability Deduplication & Prioritization
        logger.info(f"Phase 4.1: Prioritizing vulnerability findings (Max Top Findings: {max_findings})...")
        prioritizer = VulnerabilityPrioritizer()
        prioritization_result = prioritizer.prioritize(all_findings, max_findings=max_findings)

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
            ai_analysis = analyst.analyze(scan_result, http_results, prioritization_result)
            render_ai_summary(ai_analysis)
        else:
            logger.info("AI analysis skipped by user flag (--no-ai).")

        # Multi-Format Report Generation
        logger.info(f"Generating assessment reports in '{output_dir}/' (Format: {report_format})...")
        generated_files: List[str] = []

        if report_format in ["json", "all"]:
            json_file = generate_json_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir)
            generated_files.append(json_file)

        if report_format in ["markdown", "all"]:
            md_file = generate_markdown_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir)
            generated_files.append(md_file)

        if report_format in ["html", "all"]:
            html_file = generate_html_report(scan_result, http_results, prioritization_result, ai_analysis, output_dir=output_dir)
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
        output_dir=args.output_dir,
        report_format=args.format
    ))

if __name__ == "__main__":
    main()
