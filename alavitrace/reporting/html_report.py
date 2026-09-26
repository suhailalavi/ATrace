import os
import logging
from datetime import datetime
from typing import List, Optional, Any
from alavitrace import __version__
from alavitrace.core.models import ScanResult, HttpResult, Finding
from alavitrace.ai.models import AIAnalysisResult
from alavitrace.analysis.prioritization import PrioritizationResult

logger = logging.getLogger("AlaviTrace")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AlaviTrace Security Assessment - {target}</title>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1e293b;
            --border-color: #e2e8f0;
            --primary: #2563eb;
            --sev-critical: #dc2626;
            --sev-high: #ea580c;
            --sev-medium: #d97706;
            --sev-low: #2563eb;
            --sev-info: #64748b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background-color: #0f172a;
            color: #ffffff;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 24px;
        }}
        header h1 {{ margin: 0 0 10px 0; font-size: 28px; }}
        header .meta {{ color: #94a3b8; font-size: 14px; }}
        .card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        h2 {{ color: #0f172a; font-size: 20px; border-bottom: 2px solid var(--border-color); padding-bottom: 8px; margin-top: 0; }}
        h3 {{ font-size: 16px; margin-top: 16px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 14px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background-color: #f1f5f9; color: #334155; font-weight: 600; }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            color: #ffffff;
            text-transform: uppercase;
        }}
        .badge-CRITICAL {{ background-color: var(--sev-critical); }}
        .badge-HIGH {{ background-color: var(--sev-high); }}
        .badge-MEDIUM {{ background-color: var(--sev-medium); }}
        .badge-LOW {{ background-color: var(--sev-low); }}
        .badge-INFO {{ background-color: var(--sev-info); }}
        .code {{ font-family: monospace; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }}
        .disclaimer {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px 16px; font-size: 13px; color: #1e40af; margin-bottom: 20px; }}
        .vuln-summary-box {{ background: #f8fafc; border: 1px dashed #cbd5e1; border-radius: 6px; padding: 12px 16px; margin-bottom: 16px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>AlaviTrace Security Assessment</h1>
            <div class="meta">
                Target: <strong>{target}</strong> | Framework: AlaviTrace v{version} | Generated: {timestamp}
            </div>
        </header>

        <div class="disclaimer">
            <strong>Authorization & Verification Reminder:</strong> Findings are prioritized candidates for further investigation based on observed software, version/CPE correlation, severity, confidence, and exposed services. A CVE correlation does not by itself confirm that the target is vulnerable.
        </div>

        {ai_section}

        <div class="card">
            <h2>Network Reconnaissance & Services</h2>
            {recon_content}
        </div>

        {http_section}

        <div class="card">
            <h2>Prioritized Vulnerability Intelligence & Security Findings</h2>
            <div class="vuln-summary-box">
                <strong>Vulnerability Summary:</strong> Total Unique Correlated CVEs: <strong>{total_correlated}</strong> | Prioritized Candidates Displayed: <strong>{prioritized_count}</strong><br>
                <small>Severity reflects NVD database metrics and does not establish target exploitability.</small>
            </div>

            {findings_content}

            {additional_cves_note}
        </div>

        <div class="card">
            <h2>Methodology & Safety Limitations</h2>
            <ol>
                <li><strong>Reconnaissance Only:</strong> Probing was restricted to TCP service discovery, HTTP header analysis, and vulnerability intelligence matching. No automated exploitation or payload delivery was performed.</li>
                <li><strong>Human-in-the-loop:</strong> Manual verification is required to confirm whether correlated software vulnerabilities are active or mitigated in the target environment.</li>
            </ol>
        </div>
    </div>
</body>
</html>
"""

def generate_html_report(
    scan_result: ScanResult,
    http_results: List[HttpResult],
    prioritization_result: Any,
    ai_analysis: Optional[AIAnalysisResult],
    output_dir: str = "reports",
    filename_prefix: str = "alavitrace"
) -> str:
    """
    Generates a standalone HTML report displaying prioritized findings and vulnerability intelligence metrics.
    Returns absolute path to generated HTML report file.
    """
    if isinstance(prioritization_result, list):
        from alavitrace.analysis.prioritization import VulnerabilityPrioritizer
        prioritization_result = VulnerabilityPrioritizer().prioritize(prioritization_result)

    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{filename_prefix}_{timestamp_str}.html")

    target_str = scan_result.target.normalized
    prioritized_findings = prioritization_result.prioritized_findings

    # 1. AI Section HTML
    ai_html = ""
    if ai_analysis and ai_analysis.is_available:
        obs_html = "".join([f"<li>{obs}</li>" for obs in ai_analysis.key_observations])
        prio_html = "".join([f"<li>{prio}</li>" for prio in ai_analysis.investigation_priorities])
        rem_html = "".join([f"<li>{rem}</li>" for rem in ai_analysis.remediation_summary])

        ai_html = f"""
        <div class="card">
            <h2>AI-Assisted Security Analysis</h2>
            <p><strong>Executive Summary:</strong> {ai_analysis.executive_summary}</p>
            <p><strong>Attack Surface Overview:</strong> {ai_analysis.attack_surface_summary}</p>

            {"<h3>Key Observations</h3><ul>" + obs_html + "</ul>" if obs_html else ""}
            {"<h3>Investigation Priorities</h3><ol>" + prio_html + "</ol>" if prio_html else ""}
            {"<h3>Remediation Guidance</h3><ul>" + rem_html + "</ul>" if rem_html else ""}
        </div>
        """

    # 2. Reconnaissance Content HTML
    recon_lines = []
    for host in scan_result.hosts:
        host_ip = host.ipv4 or host.target.normalized
        recon_lines.append(f"<h3>Host: <span class='code'>{host_ip}</span> (Status: {host.state.upper()})</h3>")
        recon_lines.append("<table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>CPE</th></tr></thead><tbody>")
        for s in host.open_ports:
            cpe_str = ", ".join(s.cpes) if s.cpes else "N/A"
            recon_lines.append(f"<tr><td><span class='code'>{s.port}/{s.protocol}</span></td><td>{s.name}</td><td>{s.product}</td><td>{s.version}</td><td><span class='code'>{cpe_str}</span></td></tr>")
        recon_lines.append("</tbody></table>")

    recon_content = "".join(recon_lines)

    # 3. HTTP Section HTML
    http_html = ""
    if http_results:
        http_cards = []
        for h in http_results:
            if h.error_message:
                http_cards.append(f"<p>URL: <span class='code'>{h.url}</span> - Error: {h.error_message}</p>")
                continue
            missing_str = ", ".join(h.missing_security_headers) if h.missing_security_headers else "None"
            http_cards.append(f"""
            <p>URL: <span class='code'>{h.url}</span> | Status: {h.status_code} | Latency: {h.response_time_ms}ms</p>
            <p>Server Header: <span class='code'>{h.server_header or 'N/A'}</span> | Missing Headers: <span class='code'>{missing_str}</span></p>
            """)
        http_html = f"<div class='card'><h2>Passive HTTP Enumeration</h2>{''.join(http_cards)}</div>"

    # 4. Findings Content HTML
    if not prioritized_findings:
        findings_content = "<p>No specific vulnerability or security header findings identified.</p>"
    else:
        finding_rows = []
        for f in prioritized_findings:
            sev_class = f"badge-{f.severity.name}"
            finding_rows.append(f"""
            <tr>
                <td><span class="badge {sev_class}">{f.severity.value}</span></td>
                <td><strong>{f.title}</strong><br><small>{f.id}</small></td>
                <td><span class="code">{f.affected_asset}</span></td>
                <td>{f.evidence}</td>
                <td>{f.recommendation}</td>
            </tr>
            """)
        findings_content = f"""
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Finding Title</th>
                    <th>Asset</th>
                    <th>Evidence</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(finding_rows)}
            </tbody>
        </table>
        """

    additional_cves = max(0, prioritization_result.total_correlated - prioritization_result.prioritized_count)
    additional_note = f"<p style='color: #64748b; font-size: 13px;'><em>{additional_cves} additional correlated CVEs are preserved in the full JSON report.</em></p>" if additional_cves > 0 else ""

    full_html = HTML_TEMPLATE.format(
        target=target_str,
        version=__version__,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ai_section=ai_html,
        recon_content=recon_content,
        http_section=http_html,
        total_correlated=prioritization_result.total_correlated,
        prioritized_count=prioritization_result.prioritized_count,
        findings_content=findings_content,
        additional_cves_note=additional_note
    )

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(full_html)

    logger.info(f"HTML report generated at: {filepath}")
    return filepath
