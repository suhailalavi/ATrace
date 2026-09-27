import os
import logging
from datetime import datetime
from typing import List, Optional, Any
from alavitrace import __version__
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.analysis.prioritization import PrioritizationResult

logger = logging.getLogger("ATrace")

def generate_markdown_report(
    scan_result: ScanResult,
    http_results: List[HttpResult],
    prioritization_result: Any,
    ai_analysis: Optional[AIAnalysisResult],
    output_dir: str = "reports",
    filename_prefix: str = "atrace"
) -> str:
    """
    Generates a professional Markdown security assessment report featuring prioritized vulnerability intelligence.
    Returns the absolute path to the generated Markdown file.
    """
    if isinstance(prioritization_result, list):
        from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
        prioritization_result = VulnerabilityPrioritizer().prioritize(prioritization_result)

    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{filename_prefix}_{timestamp_str}.md")

    target_str = scan_result.target.normalized
    prioritized_findings = prioritization_result.prioritized_findings

    lines: List[str] = [
        f"# ATrace Security Assessment Report",
        f"**Framework Version:** ATrace v{__version__}  ",
        f"**Target Asset:** `{target_str}` ({scan_result.target.target_type})  ",
        f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "---",
        ""
    ]

    # 1. Executive Summary
    lines.append("## 1. Executive Summary")
    if ai_analysis and ai_analysis.is_available and ai_analysis.executive_summary:
        lines.append(f"{ai_analysis.executive_summary}\n")
    else:
        lines.append(f"ATrace completed automated security reconnaissance, passive HTTP inspection, and vulnerability intelligence correlation against target `{target_str}`.\n")

    # Executive Vulnerability Summary Box
    lines.append("### Vulnerability Intelligence Summary")
    lines.append(f"- **Total Correlated CVEs:** {prioritization_result.total_correlated}")
    lines.append(f"- **Prioritized Findings Displayed:** {prioritization_result.prioritized_count}")
    lines.append("> [!NOTE]\n> Severity reflects the vulnerability intelligence source (NVD) and does not establish actual target exploitability.\n")

    # 2. AI Security Analysis Section (if available)
    if ai_analysis and ai_analysis.is_available:
        lines.append("## 2. AI-Assisted Security Analysis")
        lines.append("> [!NOTE]")
        lines.append("> AI analysis is an explanatory layer operating strictly on evidence collected by deterministic scanners.")

        if ai_analysis.attack_surface_summary:
            lines.append(f"\n### Attack Surface Overview\n{ai_analysis.attack_surface_summary}\n")

        if ai_analysis.key_observations:
            lines.append("### Key Observations")
            for obs in ai_analysis.key_observations:
                lines.append(f"- {obs}")
            lines.append("")

        if ai_analysis.investigation_priorities:
            lines.append("### Recommended Manual Investigation Priorities")
            for prio in ai_analysis.investigation_priorities:
                lines.append(f"1. {prio}")
            lines.append("")

        if ai_analysis.remediation_summary:
            lines.append("### Remediation Guidance")
            for rem in ai_analysis.remediation_summary:
                lines.append(f"- {rem}")
            lines.append("")

    # 3. Discovered Services & Network Reconnaissance
    lines.append("## 3. Network Reconnaissance & Discovered Services")
    for host in scan_result.hosts:
        host_ip = host.ipv4 or host.target.normalized
        lines.append(f"### Host: `{host_ip}` (Status: {host.state.upper()})")
        if host.hostname:
            lines.append(f"- **Hostname:** `{host.hostname}`")
        if host.os_matches:
            lines.append(f"- **OS Fingerprint:** {', '.join(host.os_matches)}")

        lines.append("\n| Port / Protocol | Service Name | Product | Version | CPE Identifier |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        if not host.open_ports:
            lines.append("| - | No open ports discovered | - | - | - |")
        else:
            for s in host.open_ports:
                cpe_str = ", ".join(s.cpes) if s.cpes else "N/A"
                lines.append(f"| `{s.port}/{s.protocol}` | {s.name} | {s.product} | {s.version} | `{cpe_str}` |")
        lines.append("")

    # 4. Passive HTTP Enumeration
    if http_results:
        lines.append("## 4. Passive HTTP/HTTPS Enumeration")
        for h in http_results:
            lines.append(f"### Target URL: `{h.url}`")
            if h.error_message:
                lines.append(f"- **Status:** Connection Failed (`{h.error_message}`)\n")
                continue
            lines.append(f"- **HTTP Status:** `{h.status_code}`")
            lines.append(f"- **Final Response URL:** `{h.final_url}`")
            lines.append(f"- **Response Latency:** `{h.response_time_ms} ms`")
            if h.server_header:
                lines.append(f"- **Server Header:** `{h.server_header}`")
            if h.powered_by_header:
                lines.append(f"- **X-Powered-By Header:** `{h.powered_by_header}`")
            lines.append(f"- **Missing Security Headers:** {', '.join(h.missing_security_headers) if h.missing_security_headers else 'None'}")
            lines.append("")

    # 5. Prioritized Vulnerability Intelligence & Findings
    lines.append("## 5. Prioritized Vulnerability Intelligence & Findings")
    lines.append("> [!IMPORTANT]\n> Findings are prioritized candidates for further investigation based on observed software, version/CPE correlation, severity, confidence, and exposed services. A CVE correlation does not by itself confirm that the target is vulnerable.\n")

    if not prioritized_findings:
        lines.append("No specific vulnerabilities or security header findings identified.\n")
    else:
        lines.append("| Severity | Finding Title | Category | Confidence | Asset / Service | Evidence |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for f in prioritized_findings:
            sev_badge = f"**{f.severity.value.upper()}**"
            lines.append(f"| {sev_badge} | {f.title} | {f.category} | {f.confidence.value} | `{f.affected_asset}` | {f.evidence} |")
        lines.append("")

        lines.append("### Detailed Remediation Guidance")
        for f in prioritized_findings:
            lines.append(f"#### {f.title} (`{f.id}`)")
            lines.append(f"- **Affected Asset:** `{f.affected_asset}`")
            lines.append(f"- **Severity:** `{f.severity.value}` | **Confidence:** `{f.confidence.value}`")
            lines.append(f"- **Evidence:** {f.evidence}")
            lines.append(f"- **Recommendation:** {f.recommendation}")
            if f.references:
                lines.append(f"- **References:** [{f.references[0]}]({f.references[0]})")
            lines.append("")

        additional_cves = max(0, prioritization_result.total_correlated - prioritization_result.prioritized_count)
        if additional_cves > 0:
            lines.append("### Additional Correlated Vulnerabilities")
            lines.append(f"{additional_cves} additional correlated vulnerabilities are preserved in the full JSON report.\n")

    # 6. Limitations & Disclaimer
    lines.append("## 6. Assessment Limitations & Methodology")
    lines.append("1. **Reconnaissance Scope Only:** This assessment was generated using non-intrusive network probes, header inspection, and external CVE correlation. No active exploitation or intrusive fuzzing was performed.")
    lines.append("2. **Verification Requirement:** Software version matches and missing security headers indicate potential attack surface. Manual verification is required before confirming exploitability.")
    lines.append("3. **Authorization:** This report is intended solely for authorized security personnel.")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info(f"Markdown report generated at: {filepath}")
    return filepath
