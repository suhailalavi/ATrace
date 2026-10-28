import os
import logging
from datetime import datetime
from typing import List, Optional, Any
from alavitrace import __version__
from alavitrace.core.models import ScanResult, HttpResult, Finding, Severity
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.analysis.prioritization import PrioritizationResult

logger = logging.getLogger("AlaviTrace")

def generate_markdown_report(
    scan_result: ScanResult,
    http_results: List[HttpResult],
    prioritization_result: Any,
    ai_analysis: Optional[AIAnalysisResult],
    output_dir: str = "reports",
    filename_prefix: str = "alavitrace",
    owasp_result: Optional[Any] = None,
    attack_surface: Optional[Any] = None,
    assessment: Optional[Any] = None
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
        f"# AlaviTrace Security Assessment Report",
        f"**Framework Version:** AlaviTrace v{__version__}  ",
        f"**Target Asset:** `{target_str}` ({scan_result.target.target_type})  ",
        f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        "",
        "---",
        ""
    ]

    # 1. Executive Summary
    lines.append("## 1. Executive Summary")

    all_fs = prioritization_result.all_findings
    crit = sum(1 for f in all_fs if f.severity == Severity.CRITICAL)
    high = sum(1 for f in all_fs if f.severity == Severity.HIGH)
    med = sum(1 for f in all_fs if f.severity == Severity.MEDIUM)
    low = sum(1 for f in all_fs if f.severity == Severity.LOW)
    info = sum(1 for f in all_fs if f.severity == Severity.INFO)
    val_cnt = sum(1 for f in all_fs if getattr(f, "validation_result", None) and getattr(f.validation_result.status, "value", str(f.validation_result.status)) == "VALIDATED")

    if crit > 0:
        overall_risk = "CRITICAL"
    elif high > 0:
        overall_risk = "HIGH"
    elif med > 0:
        overall_risk = "MEDIUM"
    elif low > 0:
        overall_risk = "LOW"
    else:
        overall_risk = "INFORMATIONAL"

    lines.append(f"**Overall Assessment Risk Rating:** `{overall_risk}`\n")

    if ai_analysis and ai_analysis.is_available and ai_analysis.executive_summary:
        lines.append(f"{ai_analysis.executive_summary}\n")
    else:
        lines.append(f"AlaviTrace completed automated security reconnaissance, passive HTTP inspection, and vulnerability intelligence correlation against target `{target_str}`.\n")

    # Executive Vulnerability Summary Box
    lines.append("### Vulnerability Intelligence Summary")
    lines.append(f"- **Total Correlated CVEs:** {prioritization_result.total_correlated}")
    lines.append(f"- **Prioritized Findings Displayed:** {prioritization_result.prioritized_count}")
    lines.append("> [!NOTE]\n> Severity reflects the vulnerability intelligence source (NVD) and does not establish actual target exploitability.\n")

    lines.append("### Executive Assessment Metrics")
    lines.append("| Metric | Value |")
    lines.append("| :--- | :--- |")
    lines.append(f"| **Overall Risk Rating** | `{overall_risk}` |")
    lines.append(f"| **Total Findings** | {len(all_fs)} |")
    lines.append(f"| **Critical / High / Medium** | {crit} / {high} / {med} |")
    lines.append(f"| **Low / Informational** | {low} / {info} |")
    lines.append(f"| **Validated Findings** | {val_cnt} |")
    tot_ports = sum(len(h.open_ports) for h in scan_result.hosts)
    lines.append(f"| **Discovered Services** | {tot_ports} |")
    if attack_surface:
        lines.append(f"| **Discovered Web Endpoints** | {len(getattr(attack_surface, 'endpoints', []))} |")
    lines.append("")

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

    # Attack Surface & Web Endpoint Discovery (Phase 10)
    if attack_surface:
        lines.append("## Attack Surface & Web Endpoint Discovery")
        lines.append("> [!NOTE]")
        lines.append("> **Observed Attack Surface vs Security Findings:** Discovered endpoints, forms, parameters, and technologies represent observable application surface inventory, not confirmed security vulnerabilities.\n")

        lines.append(f"- **Base URLs:** {', '.join(f'`{u}`' for u in getattr(attack_surface, 'base_urls', [])) if getattr(attack_surface, 'base_urls', []) else 'None'}")
        lines.append(f"- **Observed HTTP Methods:** {', '.join(f'`{m}`' for m in getattr(attack_surface, 'methods', [])) if getattr(attack_surface, 'methods', []) else 'None'}")
        lines.append(f"- **Total Discovered Endpoints:** {len(getattr(attack_surface, 'endpoints', []))}")
        lines.append(f"- **Total Exposed Parameters:** {len(getattr(attack_surface, 'parameters', []))}")
        lines.append(f"- **Total Technologies Identified:** {len(getattr(attack_surface, 'technologies', []))}\n")

        techs = getattr(attack_surface, "technologies", [])
        if techs:
            lines.append("### Identified Technologies")
            lines.append("| Technology | Version | Detection Source | Confidence |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for t in techs:
                ver_str = t.version if getattr(t, "version", None) else "Unknown"
                conf_str = t.confidence.value if hasattr(t.confidence, "value") else str(t.confidence)
                lines.append(f"| **{t.name}** | `{ver_str}` | {t.source} | {conf_str} |")
            lines.append("")

        endpoints = getattr(attack_surface, "endpoints", [])
        if endpoints:
            lines.append("### Discovered Web Endpoints")
            lines.append("| Method | Path | Status | Parameters | Source |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for ep in endpoints[:25]:
                status_str = f"`{ep.status_code}`" if ep.status_code else "-"
                params_str = ", ".join(f"`{p}`" for p in ep.parameters) if ep.parameters else "-"
                lines.append(f"| `{ep.method}` | `{ep.path}` | {status_str} | {params_str} | {ep.source} |")
            if len(endpoints) > 25:
                lines.append(f"\n*...and {len(endpoints) - 25} additional endpoints preserved in full JSON report.*")
            lines.append("")

        params = getattr(attack_surface, "parameters", [])
        if params:
            lines.append("### Observed Parameters")
            param_names = sorted(list(set(getattr(p, 'name', str(p)) for p in params)))
            lines.append(", ".join(f"`{p}`" for p in param_names[:30]))
            if len(param_names) > 30:
                lines.append(f"... (+{len(param_names) - 30} more)")
            lines.append("\n")

        redirects = getattr(attack_surface, "redirects", [])
        if redirects:
            lines.append("### Observed Redirects")
            for red in redirects:
                flag_str = f" **[{red.flag}]**" if getattr(red, 'flag', None) else ""
                lines.append(f"- `{red.source_url}` -> `{red.target_url}`{flag_str}")
            lines.append("")

    # 5. OWASP Web Security Assessment
    if owasp_result:
        lines.append("## 5. OWASP Web Security Assessment")
        if not getattr(owasp_result, "is_http_available", False):
            lines.append("No HTTP/HTTPS service detected; OWASP web assessment skipped.\n")
        else:
            owasp_findings = getattr(owasp_result, "findings", [])
            if not owasp_findings:
                lines.append("No specific OWASP web vulnerabilities identified.\n")
            else:
                crit = sum(1 for f in owasp_findings if f.severity == Severity.CRITICAL)
                high = sum(1 for f in owasp_findings if f.severity == Severity.HIGH)
                med = sum(1 for f in owasp_findings if f.severity == Severity.MEDIUM)
                low = sum(1 for f in owasp_findings if f.severity == Severity.LOW)
                info = sum(1 for f in owasp_findings if f.severity == Severity.INFO)
                lines.append(f"**Total Findings:** {len(owasp_findings)} | **Critical:** {crit} | **High:** {high} | **Medium:** {med} | **Low:** {low} | **Informational:** {info}\n")
                lines.append("> [!NOTE]\n> OWASP web security findings represent deterministic, non-destructive heuristic indicators. Candidate findings require manual validation.\n")
                lines.append("| Severity | Finding Title | OWASP Category | Confidence | Endpoint | Evidence | Limitations |")
                lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
                for f in owasp_findings:
                    sev_badge = f"**{f.severity.value.upper()}**"
                    owasp_cat = f.owasp_category or "N/A"
                    lim = getattr(f, "limitations", "") or "Manual verification required."
                    lines.append(f"| {sev_badge} | {f.title} | {owasp_cat} | {f.confidence.value} | `{f.endpoint or f.affected_asset}` | {f.evidence} | {lim} |")
                lines.append("")

                a03_findings = [
                    f for f in owasp_findings
                    if (getattr(f, "owasp_category", None) and "A03" in f.owasp_category)
                    or "Injection" in f.title or "XSS" in f.title
                ]
                if a03_findings:
                    sqli = sum(1 for f in a03_findings if "SQL" in f.title)
                    xss = sum(1 for f in a03_findings if "XSS" in f.title)
                    cmd = sum(1 for f in a03_findings if "Command" in f.title)
                    lines.append("### A03:2021 Injection Assessment Summary")
                    lines.append(f"- **Total Injection Candidates:** {len(a03_findings)}")
                    lines.append(f"- **SQL Injection Candidates:** {sqli}")
                    lines.append(f"- **Reflected XSS Candidates:** {xss}")
                    lines.append(f"- **Command Injection Candidates:** {cmd}\n")

                a05_findings = [
                    f for f in owasp_findings
                    if getattr(f, "owasp_category", None) and "A05" in f.owasp_category
                ]
                if a05_findings:
                    lines.append("### A05:2021 Security Misconfiguration Summary")
                    lines.append(f"- **Total Security Misconfigurations:** {len(a05_findings)}")
                    for mf in a05_findings[:5]:
                        lines.append(f"  - [{mf.severity.value.upper()}] **{mf.title}**: {mf.evidence}")
                    lines.append("")

                a06_findings = [
                    f for f in owasp_findings
                    if getattr(f, "owasp_category", None) and "A06" in f.owasp_category
                ]
                if a06_findings:
                    lines.append("### A06:2021 Vulnerable and Outdated Components Summary")
                    lines.append(f"- **Total Vulnerable/Outdated Components:** {len(a06_findings)}")
                    for vf in a06_findings[:5]:
                        lines.append(f"  - [{vf.severity.value.upper()}] **{vf.title}**: {vf.evidence}")
                    lines.append("")

    # OWASP Top 10 (2021) Coverage Matrix
    from alavitrace.assessment.coverage import get_owasp_coverage_summary
    owasp_cov = get_owasp_coverage_summary(prioritization_result.all_findings)
    lines.append("## OWASP Top 10 (2021) Coverage Matrix")
    lines.append("| Category | Name | Support Level | Findings Count | Detection & Validation Capabilities |")
    lines.append("| :--- | :--- | :--- | :--- | :--- |")
    for code, item in owasp_cov.categories.items():
        cap_summary = "; ".join(item.capabilities[:2]) if item.capabilities else item.limitations[0][:80] + "..."
        lines.append(f"| `{item.code}` | {item.name} | **{item.support_level}** | {item.findings_count} | {cap_summary} |")
    lines.append("")
    for note in owasp_cov.summary_notes:
        lines.append(f"- *{note}*")
    lines.append("")

    # 6. Prioritized Vulnerability Intelligence & Findings
    lines.append("## 6. Prioritized Vulnerability Intelligence & Findings" if owasp_result else "## 5. Prioritized Vulnerability Intelligence & Findings")
    lines.append("> [!IMPORTANT]\n> Findings are prioritized candidates for further investigation based on observed software, version/CPE correlation, severity, confidence, and exposed services. A CVE correlation does not by itself confirm that the target is vulnerable.\n")

    has_validation = any(getattr(f, "validation_result", None) is not None for f in prioritized_findings)

    if not prioritized_findings:
        lines.append("No specific vulnerabilities or security header findings identified.\n")
    else:
        if has_validation:
            lines.append("### Controlled Finding Validation Summary (Phase 9)")
            lines.append("| Status | Finding Title | Method | Validation Evidence | Limitations |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for f in prioritized_findings:
                if getattr(f, "validation_result", None):
                    vr = f.validation_result
                    status_str = f"**`{vr.status.value}`**"
                    lim_str = vr.limitations or "N/A"
                    lines.append(f"| {status_str} | {f.title} | {vr.validation_method} | {vr.evidence} | {lim_str} |")
            lines.append("")

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
            if getattr(f, "validation_result", None):
                vr = f.validation_result
                lines.append(f"- **Validation Status:** `{vr.status.value}` ({vr.validation_method})")
                lines.append(f"- **Validation Evidence:** {vr.evidence}")
                if getattr(vr, "limitations", None):
                    lines.append(f"- **Validation Limitations:** {vr.limitations}")
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
